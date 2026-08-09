from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import os
import re
import secrets
import sqlite3
import stat as stat_module
import struct
import tempfile
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


LOGGER = logging.getLogger("codex_image_pruner")

SUPPORTED_IMAGE_MIMES = {
    "image/gif",
    "image/jpeg",
    "image/png",
    "image/webp",
}
MAX_IMAGES_PER_SESSION = 2_000
MAX_PREVIEW_BYTES = 128 * 1024 * 1024
PLACEHOLDER_TEXT = "[Image removed locally by Codex 413 Fix]"
HEX_ID_RE = re.compile(r"^[0-9a-f]{64}$")
SNAPSHOT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{24,64}$")


class PrunerError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        status: int = 400,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.details = details


@dataclass(frozen=True)
class ThreadRecord:
    thread_id: str
    rollout_path: Path
    title: str
    cwd: str
    source: str
    created_at: int
    updated_at: int


@dataclass(frozen=True)
class FileFingerprint:
    size: int
    mtime_ns: int
    sha256: str


@dataclass(frozen=True)
class ImageRef:
    image_id: str
    line_number: int
    container: str
    index: int
    pointer: str
    uri_sha256: str
    mime_type: str
    encoded_chars: int
    decoded_bytes: int
    source: str
    timestamp: str | None
    detail: str | None
    width: int | None
    height: int | None

    def public_dict(self, snapshot_id: str) -> dict[str, Any]:
        return {
            "id": self.image_id,
            "line_number": self.line_number,
            "source": self.source,
            "timestamp": self.timestamp,
            "mime_type": self.mime_type,
            "encoded_chars": self.encoded_chars,
            "decoded_bytes": self.decoded_bytes,
            "detail": self.detail,
            "width": self.width,
            "height": self.height,
            "preview_url": f"/api/image/{snapshot_id}/{self.image_id}",
        }


@dataclass(frozen=True)
class ScanSnapshot:
    snapshot_id: str
    created_monotonic: float
    thread: ThreadRecord
    fingerprint: FileFingerprint
    line_count: int
    images: dict[str, ImageRef]


class SnapshotStore:
    def __init__(self, ttl_seconds: int = 30 * 60, max_entries: int = 32) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._items: OrderedDict[str, ScanSnapshot] = OrderedDict()
        self._lock = threading.RLock()

    def add(self, snapshot: ScanSnapshot) -> None:
        with self._lock:
            self._purge_locked()
            self._items[snapshot.snapshot_id] = snapshot
            self._items.move_to_end(snapshot.snapshot_id)
            while len(self._items) > self.max_entries:
                self._items.popitem(last=False)

    def get(self, snapshot_id: str) -> ScanSnapshot:
        if not isinstance(snapshot_id, str) or not SNAPSHOT_ID_RE.fullmatch(snapshot_id):
            raise PrunerError("INVALID_SNAPSHOT_ID", "Invalid scan snapshot ID.", 422)

        with self._lock:
            self._purge_locked()
            snapshot = self._items.get(snapshot_id)
            if snapshot is None:
                raise PrunerError(
                    "SNAPSHOT_NOT_FOUND",
                    "The scan snapshot is missing or expired. Scan the conversation again.",
                    404,
                )
            self._items.move_to_end(snapshot_id)
            return snapshot

    def invalidate_path(self, path: Path) -> None:
        path_key = os.path.normcase(str(path))
        with self._lock:
            stale_ids = [
                snapshot_id
                for snapshot_id, snapshot in self._items.items()
                if os.path.normcase(str(snapshot.thread.rollout_path)) == path_key
            ]
            for snapshot_id in stale_ids:
                self._items.pop(snapshot_id, None)

    def _purge_locked(self) -> None:
        cutoff = time.monotonic() - self.ttl_seconds
        expired = [
            snapshot_id
            for snapshot_id, snapshot in self._items.items()
            if snapshot.created_monotonic < cutoff
        ]
        for snapshot_id in expired:
            self._items.pop(snapshot_id, None)


class SessionImagePruner:
    def __init__(
        self,
        codex_home: Path | None = None,
        state_db: Path | None = None,
        trusted_roots: Iterable[Path] | None = None,
        snapshot_ttl_seconds: int = 30 * 60,
        max_snapshots: int = 32,
    ) -> None:
        configured_home = os.environ.get("CODEX_HOME")
        self.codex_home = Path(
            codex_home
            if codex_home is not None
            else configured_home
            if configured_home
            else Path.home() / ".codex"
        ).expanduser().resolve()
        self.state_db = Path(state_db or self.codex_home / "state_5.sqlite").expanduser().resolve()
        roots = trusted_roots or (
            self.codex_home / "sessions",
            self.codex_home / "archived_sessions",
        )
        self.trusted_roots = tuple(Path(root).expanduser().resolve() for root in roots)
        self.backup_root = self.codex_home / "backup" / "image-pruner"
        self.audit_path = self.codex_home / "log" / "codex-413-fix-audit.jsonl"
        self.snapshots = SnapshotStore(snapshot_ttl_seconds, max_snapshots)
        self._mutation_lock = threading.RLock()
        self._audit_lock = threading.Lock()

    def scan(self, thread_id: str) -> dict[str, Any]:
        normalized_id = normalize_thread_id(thread_id)
        thread = self._lookup_thread(normalized_id)
        rollout_path = self._validate_rollout_path(thread.rollout_path)
        thread = ThreadRecord(
            thread_id=thread.thread_id,
            rollout_path=rollout_path,
            title=thread.title,
            cwd=thread.cwd,
            source=thread.source,
            created_at=thread.created_at,
            updated_at=thread.updated_at,
        )

        before = safe_stat(rollout_path)
        images, line_count, digest, byte_count = self._scan_rollout(rollout_path)
        after = safe_stat(rollout_path)
        if (
            before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or byte_count != after.st_size
        ):
            raise PrunerError(
                "SESSION_CHANGED_DURING_SCAN",
                "The session changed while it was being scanned. Scan it again.",
                409,
            )

        fingerprint = FileFingerprint(
            size=after.st_size,
            mtime_ns=after.st_mtime_ns,
            sha256=digest,
        )
        snapshot_id = secrets.token_urlsafe(24)
        snapshot = ScanSnapshot(
            snapshot_id=snapshot_id,
            created_monotonic=time.monotonic(),
            thread=thread,
            fingerprint=fingerprint,
            line_count=line_count,
            images={image.image_id: image for image in images},
        )
        self.snapshots.add(snapshot)

        encoded_total = sum(image.encoded_chars for image in images)
        decoded_total = sum(image.decoded_bytes for image in images)
        source_counts = {
            "user": sum(image.source == "user" for image in images),
            "tool": sum(image.source == "tool" for image in images),
            "other": sum(image.source == "other" for image in images),
        }
        return {
            "snapshot_id": snapshot_id,
            "thread": {
                "id": thread.thread_id,
                "title": bounded_single_line(thread.title, 180),
                "cwd": bounded_text(thread.cwd, 4096),
                "source": bounded_text(thread.source, 100),
                "created_at": thread.created_at,
                "updated_at": thread.updated_at,
            },
            "file": {
                "path": str(rollout_path),
                "size": fingerprint.size,
                "mtime_ns": fingerprint.mtime_ns,
                "sha256": fingerprint.sha256,
                "line_count": line_count,
            },
            "summary": {
                "image_count": len(images),
                "encoded_chars": encoded_total,
                "decoded_bytes": decoded_total,
                "source_counts": source_counts,
            },
            "images": [image.public_dict(snapshot_id) for image in images],
        }

    def get_image(self, snapshot_id: str, image_id: str) -> tuple[bytes, str]:
        snapshot = self.snapshots.get(snapshot_id)
        ref = self._get_image_ref(snapshot, image_id)
        self._assert_quick_current(snapshot)
        raw_line = read_line(snapshot.thread.rollout_path, ref.line_number)
        item = locate_image_item(raw_line, ref)
        image_url = item.get("image_url")
        if not isinstance(image_url, str):
            raise PrunerError("IMAGE_CHANGED", "The image no longer matches the scan.", 409)
        uri_digest = sha256_text(image_url)
        if uri_digest != ref.uri_sha256:
            raise PrunerError("IMAGE_CHANGED", "The image no longer matches the scan.", 409)

        mime_type, payload = split_data_uri(image_url)
        if mime_type != ref.mime_type:
            raise PrunerError("IMAGE_CHANGED", "The image no longer matches the scan.", 409)
        if ref.decoded_bytes > MAX_PREVIEW_BYTES:
            raise PrunerError(
                "IMAGE_TOO_LARGE",
                "This image is too large to preview safely.",
                413,
            )
        try:
            decoded = base64.b64decode(payload, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise PrunerError("INVALID_IMAGE_DATA", "The stored image data is invalid.", 422) from exc
        if len(decoded) > MAX_PREVIEW_BYTES:
            raise PrunerError(
                "IMAGE_TOO_LARGE",
                "This image is too large to preview safely.",
                413,
            )
        return decoded, mime_type

    def prune(
        self,
        snapshot_id: str,
        image_ids: list[str],
        writer_stopped: bool,
    ) -> dict[str, Any]:
        if writer_stopped is not True:
            raise PrunerError(
                "WRITER_ACK_REQUIRED",
                "Confirm that the target Codex conversation is no longer writing.",
                422,
            )
        if not isinstance(image_ids, list) or not 1 <= len(image_ids) <= MAX_IMAGES_PER_SESSION:
            raise PrunerError(
                "INVALID_IMAGE_SELECTION",
                "Select between 1 and 2000 images.",
                422,
            )
        if any(not isinstance(image_id, str) or not HEX_ID_RE.fullmatch(image_id) for image_id in image_ids):
            raise PrunerError("INVALID_IMAGE_SELECTION", "The image selection is invalid.", 422)
        if len(set(image_ids)) != len(image_ids):
            raise PrunerError("DUPLICATE_IMAGE_ID", "The image selection contains duplicates.", 422)

        snapshot = self.snapshots.get(snapshot_id)
        selected = [self._get_image_ref(snapshot, image_id) for image_id in image_ids]
        target = snapshot.thread.rollout_path

        with self._mutation_lock:
            self._assert_full_current(snapshot)
            self._append_audit(
                {
                    "event": "prune_requested",
                    "thread_id": snapshot.thread.thread_id,
                    "snapshot_id": snapshot.snapshot_id,
                    "rollout_sha256": snapshot.fingerprint.sha256,
                    "image_ids": image_ids,
                },
                required=True,
            )

            source_stat = safe_stat(target)
            temp_path: Path | None = None
            try:
                temp_path, rewritten_size = self._build_rewrite(snapshot, selected, source_stat)
                backup_path = self._create_verified_backup(snapshot, source_stat)
                self._assert_full_current(snapshot)
                install_mode = self._install_rewrite(
                    snapshot,
                    temp_path,
                    target,
                    backup_path,
                    rewritten_size,
                )
                temp_path = None
                sync_directory(target.parent)
            except PermissionError as exc:
                raise PrunerError(
                    "PERMISSION_DENIED",
                    "The session or backup file could not be written.",
                    403,
                ) from exc
            except OSError as exc:
                raise PrunerError(
                    "FILESYSTEM_ERROR",
                    "The session could not be rewritten safely.",
                    500,
                ) from exc
            finally:
                if temp_path is not None:
                    unlink_quietly(temp_path)

            removed_decoded = sum(image.decoded_bytes for image in selected)
            removed_encoded = sum(image.encoded_chars for image in selected)
            result = {
                "thread_id": snapshot.thread.thread_id,
                "removed_count": len(selected),
                "removed_decoded_bytes": removed_decoded,
                "removed_encoded_chars": removed_encoded,
                "previous_file_size": snapshot.fingerprint.size,
                "new_file_size": rewritten_size,
                "freed_file_bytes": snapshot.fingerprint.size - rewritten_size,
                "backup_path": str(backup_path),
                "install_mode": install_mode,
            }
            self.snapshots.invalidate_path(target)
            self._append_audit(
                {
                    "event": "prune_succeeded",
                    "thread_id": snapshot.thread.thread_id,
                    "snapshot_id": snapshot.snapshot_id,
                    "rollout_sha256_before": snapshot.fingerprint.sha256,
                    "backup_path": str(backup_path),
                    "install_mode": install_mode,
                    "previous_file_size": snapshot.fingerprint.size,
                    "new_file_size": rewritten_size,
                    "images": [
                        {
                            "image_id": image.image_id,
                            "uri_sha256": image.uri_sha256,
                            "line_number": image.line_number,
                            "source": image.source,
                            "decoded_bytes": image.decoded_bytes,
                            "encoded_chars": image.encoded_chars,
                        }
                        for image in selected
                    ],
                },
                required=False,
            )
            return result

    def _install_rewrite(
        self,
        snapshot: ScanSnapshot,
        temp_path: Path,
        target: Path,
        backup_path: Path,
        rewritten_size: int,
    ) -> str:
        try:
            os.replace(temp_path, target)
            return "atomic_replace"
        except PermissionError:
            if os.name != "nt":
                raise

        # Codex can keep a Windows handle open without FILE_SHARE_DELETE even
        # after generation stops. In that case replacement is impossible, but
        # an exclusive byte-range lock still allows a verified in-place write.
        try:
            self._install_locked_in_place(
                snapshot,
                temp_path,
                target,
                backup_path,
                rewritten_size,
            )
        finally:
            unlink_quietly(temp_path)
        return "locked_in_place"

    def _install_locked_in_place(
        self,
        snapshot: ScanSnapshot,
        temp_path: Path,
        target: Path,
        backup_path: Path,
        rewritten_size: int,
    ) -> None:
        import msvcrt

        lock_length = max(1, snapshot.fingerprint.size, rewritten_size)
        if lock_length > 2_000_000_000:
            raise PrunerError(
                "FILE_IN_USE",
                "The session is locked and too large for the Windows in-place fallback.",
                409,
            )

        try:
            target_handle = target.open("r+b")
        except PermissionError as exc:
            raise PrunerError(
                "FILE_IN_USE",
                "The target session is still exclusively locked by Codex.",
                409,
            ) from exc

        locked = False
        try:
            target_handle.seek(0)
            try:
                msvcrt.locking(target_handle.fileno(), msvcrt.LK_NBLCK, lock_length)
                locked = True
            except OSError as exc:
                raise PrunerError(
                    "FILE_IN_USE",
                    "The target session is still being written. Stop it and scan again.",
                    409,
                ) from exc

            current_hash, current_size = sha256_open_file(target_handle)
            if (
                current_hash != snapshot.fingerprint.sha256
                or current_size != snapshot.fingerprint.size
            ):
                raise PrunerError(
                    "SNAPSHOT_STALE",
                    "The session changed before the locked rewrite. Scan it again.",
                    409,
                )

            expected_hash, expected_size = sha256_file(temp_path)
            if expected_size != rewritten_size:
                raise PrunerError(
                    "REWRITE_VALIDATION_FAILED",
                    "The prepared rewrite has an unexpected size.",
                    500,
                )

            try:
                copy_path_to_open_file(temp_path, target_handle)
                written_hash, written_size = sha256_open_file(target_handle)
                if written_hash != expected_hash or written_size != expected_size:
                    raise OSError("The in-place rewrite did not verify.")
            except Exception as write_error:
                try:
                    copy_path_to_open_file(backup_path, target_handle)
                    restored_hash, restored_size = sha256_open_file(target_handle)
                    if (
                        restored_hash != snapshot.fingerprint.sha256
                        or restored_size != snapshot.fingerprint.size
                    ):
                        raise OSError("The restored session did not verify.")
                except Exception as restore_error:
                    raise PrunerError(
                        "RECOVERY_FAILED",
                        "The rewrite failed and automatic recovery also failed. Use the reported backup.",
                        500,
                        {"backup_path": str(backup_path)},
                    ) from restore_error
                raise PrunerError(
                    "IN_PLACE_REWRITE_FAILED",
                    "The Windows in-place rewrite failed; the original was restored from backup.",
                    500,
                ) from write_error
        finally:
            if locked:
                try:
                    target_handle.seek(0)
                    msvcrt.locking(target_handle.fileno(), msvcrt.LK_UNLCK, lock_length)
                except OSError:
                    LOGGER.exception("Failed to release the session file lock")
            target_handle.close()

    def _lookup_thread(self, thread_id: str) -> ThreadRecord:
        if not self.state_db.is_file():
            raise PrunerError(
                "STATE_DB_NOT_FOUND",
                "The Codex thread index was not found.",
                404,
            )
        uri = f"{self.state_db.as_uri()}?mode=ro"
        try:
            connection = sqlite3.connect(uri, uri=True, timeout=3.0)
            connection.execute("PRAGMA query_only = ON")
            row = connection.execute(
                """
                SELECT id, rollout_path, title, cwd, source, created_at, updated_at
                FROM threads
                WHERE id = ?
                """,
                (thread_id,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise PrunerError(
                "STATE_DB_ERROR",
                "The Codex thread index could not be read.",
                500,
            ) from exc
        finally:
            if "connection" in locals():
                connection.close()

        if row is None:
            raise PrunerError("THREAD_NOT_FOUND", "No Codex conversation matched that ID.", 404)
        return ThreadRecord(
            thread_id=str(row[0]),
            rollout_path=Path(str(row[1])),
            title=str(row[2] or "Untitled conversation"),
            cwd=str(row[3] or ""),
            source=str(row[4] or ""),
            created_at=int(row[5] or 0),
            updated_at=int(row[6] or 0),
        )

    def _validate_rollout_path(self, rollout_path: Path) -> Path:
        candidate = rollout_path.expanduser()
        if not candidate.is_absolute():
            candidate = self.codex_home / candidate
        try:
            candidate = candidate.resolve(strict=True)
        except (FileNotFoundError, OSError) as exc:
            raise PrunerError("ROLLOUT_NOT_FOUND", "The conversation rollout file was not found.", 404) from exc
        if candidate.suffix.lower() != ".jsonl" or not candidate.is_file():
            raise PrunerError("INVALID_ROLLOUT", "The indexed rollout is not a JSONL file.", 422)
        if not any(path_is_within(candidate, root) for root in self.trusted_roots):
            raise PrunerError(
                "UNTRUSTED_ROLLOUT_PATH",
                "The indexed rollout is outside the trusted Codex session directories.",
                403,
            )
        return candidate

    def _scan_rollout(self, path: Path) -> tuple[list[ImageRef], int, str, int]:
        images: list[ImageRef] = []
        digest = hashlib.sha256()
        line_count = 0
        byte_count = 0
        try:
            with path.open("rb") as handle:
                for line_count, raw_line in enumerate(handle, start=1):
                    digest.update(raw_line)
                    byte_count += len(raw_line)
                    if not raw_line.strip():
                        continue
                    record = parse_json_line(raw_line, line_count)
                    images.extend(discover_images(record, line_count))
                    if len(images) > MAX_IMAGES_PER_SESSION:
                        raise PrunerError(
                            "TOO_MANY_IMAGES",
                            "The conversation contains more than 2000 persisted images.",
                            422,
                        )
        except PermissionError as exc:
            raise PrunerError("PERMISSION_DENIED", "The conversation rollout cannot be read.", 403) from exc
        except OSError as exc:
            raise PrunerError("ROLLOUT_READ_ERROR", "The conversation rollout could not be read.", 500) from exc
        return images, line_count, digest.hexdigest(), byte_count

    def _get_image_ref(self, snapshot: ScanSnapshot, image_id: str) -> ImageRef:
        if not isinstance(image_id, str) or not HEX_ID_RE.fullmatch(image_id):
            raise PrunerError("INVALID_IMAGE_ID", "Invalid image ID.", 422)
        ref = snapshot.images.get(image_id)
        if ref is None:
            raise PrunerError("IMAGE_NOT_FOUND", "The image is not part of this scan.", 404)
        return ref

    def _assert_quick_current(self, snapshot: ScanSnapshot) -> None:
        current = safe_stat(snapshot.thread.rollout_path)
        if (
            current.st_size != snapshot.fingerprint.size
            or current.st_mtime_ns != snapshot.fingerprint.mtime_ns
        ):
            raise PrunerError(
                "SNAPSHOT_STALE",
                "The session changed after scanning. Scan it again.",
                409,
            )

    def _assert_full_current(self, snapshot: ScanSnapshot) -> None:
        self._assert_quick_current(snapshot)
        current_hash, current_size = sha256_file(snapshot.thread.rollout_path)
        current_stat = safe_stat(snapshot.thread.rollout_path)
        if (
            current_hash != snapshot.fingerprint.sha256
            or current_size != snapshot.fingerprint.size
            or current_stat.st_size != snapshot.fingerprint.size
            or current_stat.st_mtime_ns != snapshot.fingerprint.mtime_ns
        ):
            raise PrunerError(
                "SNAPSHOT_STALE",
                "The session changed after scanning. Scan it again.",
                409,
            )

    def _build_rewrite(
        self,
        snapshot: ScanSnapshot,
        selected: list[ImageRef],
        source_stat: os.stat_result,
    ) -> tuple[Path, int]:
        refs_by_line: dict[int, list[ImageRef]] = {}
        for ref in selected:
            refs_by_line.setdefault(ref.line_number, []).append(ref)

        descriptor, raw_temp_path = tempfile.mkstemp(
            prefix=f".{snapshot.thread.rollout_path.name}.image-pruner-",
            suffix=".tmp",
            dir=snapshot.thread.rollout_path.parent,
        )
        os.close(descriptor)
        temp_path = Path(raw_temp_path)
        source_hash = hashlib.sha256()
        source_bytes = 0
        output_bytes = 0
        found_ids: set[str] = set()

        try:
            with snapshot.thread.rollout_path.open("rb") as source, temp_path.open("wb") as destination:
                for line_number, raw_line in enumerate(source, start=1):
                    source_hash.update(raw_line)
                    source_bytes += len(raw_line)
                    refs = refs_by_line.get(line_number)
                    if refs:
                        output_line, line_found = rewrite_line(raw_line, line_number, refs)
                        found_ids.update(line_found)
                    else:
                        output_line = raw_line
                    destination.write(output_line)
                    output_bytes += len(output_line)
                destination.flush()
                os.fsync(destination.fileno())

            if found_ids != {image.image_id for image in selected}:
                raise PrunerError(
                    "IMAGE_CHANGED",
                    "One or more selected images no longer match the scan.",
                    409,
                )
            after = safe_stat(snapshot.thread.rollout_path)
            if (
                source_hash.hexdigest() != snapshot.fingerprint.sha256
                or source_bytes != snapshot.fingerprint.size
                or after.st_size != snapshot.fingerprint.size
                or after.st_mtime_ns != snapshot.fingerprint.mtime_ns
            ):
                raise PrunerError(
                    "SNAPSHOT_STALE",
                    "The session changed while preparing the rewrite. Scan it again.",
                    409,
                )
            os.chmod(temp_path, stat_module.S_IMODE(source_stat.st_mode))
            return temp_path, output_bytes
        except Exception:
            unlink_quietly(temp_path)
            raise

    def _create_verified_backup(
        self,
        snapshot: ScanSnapshot,
        source_stat: os.stat_result,
    ) -> Path:
        backup_dir = self.backup_root / snapshot.thread.thread_id
        backup_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        backup_name = (
            f"{timestamp}-{snapshot.fingerprint.sha256[:12]}-"
            f"{snapshot.thread.rollout_path.name}.bak"
        )
        final_path = backup_dir / backup_name
        descriptor, raw_temp_path = tempfile.mkstemp(prefix=".backup-", suffix=".tmp", dir=backup_dir)
        os.close(descriptor)
        temp_path = Path(raw_temp_path)
        backup_hash = hashlib.sha256()
        backup_size = 0

        try:
            with snapshot.thread.rollout_path.open("rb") as source, temp_path.open("wb") as destination:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    backup_hash.update(chunk)
                    backup_size += len(chunk)
                    destination.write(chunk)
                destination.flush()
                os.fsync(destination.fileno())

            after = safe_stat(snapshot.thread.rollout_path)
            if (
                backup_hash.hexdigest() != snapshot.fingerprint.sha256
                or backup_size != snapshot.fingerprint.size
                or after.st_size != snapshot.fingerprint.size
                or after.st_mtime_ns != snapshot.fingerprint.mtime_ns
            ):
                raise PrunerError(
                    "SNAPSHOT_STALE",
                    "The session changed while creating the backup. Scan it again.",
                    409,
                )
            os.chmod(temp_path, stat_module.S_IMODE(source_stat.st_mode))
            os.replace(temp_path, final_path)
            temp_path = Path()
            sync_directory(backup_dir)
            return final_path
        finally:
            if temp_path != Path():
                unlink_quietly(temp_path)

    def _append_audit(self, event: dict[str, Any], required: bool) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **event,
        }
        try:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            encoded = (json.dumps(entry, ensure_ascii=True, separators=(",", ":")) + "\n").encode("utf-8")
            with self._audit_lock, self.audit_path.open("ab") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            if required:
                raise PrunerError(
                    "AUDIT_LOG_UNAVAILABLE",
                    "The security audit log cannot be written, so no changes were made.",
                    500,
                ) from exc
            LOGGER.exception("Failed to record completed prune audit event")


def normalize_thread_id(value: str) -> str:
    if not isinstance(value, str) or len(value) > 64:
        raise PrunerError("INVALID_THREAD_ID", "Enter a valid conversation UUID.", 422)
    try:
        normalized = str(uuid.UUID(value.strip()))
    except (ValueError, AttributeError) as exc:
        raise PrunerError("INVALID_THREAD_ID", "Enter a valid conversation UUID.", 422) from exc
    if value.strip().lower() != normalized:
        raise PrunerError("INVALID_THREAD_ID", "Enter the full canonical conversation UUID.", 422)
    return normalized


def bounded_text(value: str, limit: int) -> str:
    cleaned = "".join(char for char in value if char >= " " or char in "\t\n")
    return cleaned[:limit]


def bounded_single_line(value: str, limit: int) -> str:
    normalized = " ".join(value.split())
    if len(normalized) <= limit:
        return normalized
    return normalized[: max(0, limit - 3)].rstrip() + "..."


def path_is_within(candidate: Path, root: Path) -> bool:
    candidate_key = canonical_path_key(candidate)
    root_key = canonical_path_key(root)
    try:
        return os.path.commonpath((candidate_key, root_key)) == root_key
    except ValueError:
        return False


def canonical_path_key(path: Path) -> str:
    value = os.path.abspath(str(path))
    if os.name == "nt":
        if value.startswith("\\\\?\\UNC\\"):
            value = "\\\\" + value[8:]
        elif value.startswith("\\\\?\\"):
            value = value[4:]
    return os.path.normcase(os.path.normpath(value))


def safe_stat(path: Path) -> os.stat_result:
    try:
        return path.stat()
    except FileNotFoundError as exc:
        raise PrunerError("ROLLOUT_NOT_FOUND", "The conversation rollout file was not found.", 404) from exc
    except PermissionError as exc:
        raise PrunerError("PERMISSION_DENIED", "The conversation rollout cannot be accessed.", 403) from exc
    except OSError as exc:
        raise PrunerError("ROLLOUT_READ_ERROR", "The conversation rollout could not be inspected.", 500) from exc


def parse_json_line(raw_line: bytes, line_number: int) -> dict[str, Any]:
    try:
        value = json.loads(raw_line)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise PrunerError(
            "INVALID_JSONL",
            f"The rollout contains invalid JSON at line {line_number}.",
            422,
        ) from exc
    if not isinstance(value, dict):
        raise PrunerError(
            "INVALID_JSONL",
            f"The rollout contains a non-object record at line {line_number}.",
            422,
        )
    return value


def discover_images(record: dict[str, Any], line_number: int) -> list[ImageRef]:
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return []
    source = classify_source(payload)
    timestamp_value = record.get("timestamp")
    timestamp = bounded_text(timestamp_value, 100) if isinstance(timestamp_value, str) else None
    discovered: list[ImageRef] = []

    for container in ("content", "output"):
        items = payload.get(container)
        if not isinstance(items, list):
            continue
        for index, item in enumerate(items):
            if not isinstance(item, dict) or item.get("type") != "input_image":
                continue
            image_url = item.get("image_url")
            if not isinstance(image_url, str) or not image_url.startswith("data:"):
                continue
            try:
                mime_type, encoded_payload = split_data_uri(image_url)
            except PrunerError:
                continue
            uri_digest = sha256_text(image_url)
            pointer = f"/payload/{container}/{index}"
            image_id = make_image_id(line_number, pointer, uri_digest)
            detail_value = item.get("detail")
            detail = bounded_text(detail_value, 50) if isinstance(detail_value, str) else None
            width, height = image_dimensions(mime_type, encoded_payload)
            discovered.append(
                ImageRef(
                    image_id=image_id,
                    line_number=line_number,
                    container=container,
                    index=index,
                    pointer=pointer,
                    uri_sha256=uri_digest,
                    mime_type=mime_type,
                    encoded_chars=len(image_url),
                    decoded_bytes=estimated_base64_size(encoded_payload),
                    source=source,
                    timestamp=timestamp,
                    detail=detail,
                    width=width,
                    height=height,
                )
            )
    return discovered


def classify_source(payload: dict[str, Any]) -> str:
    payload_type = payload.get("type")
    if payload_type == "message" and payload.get("role") == "user":
        return "user"
    if payload_type == "custom_tool_call_output":
        return "tool"
    return "other"


def split_data_uri(image_url: str) -> tuple[str, str]:
    header, separator, payload = image_url.partition(",")
    if not separator or not header.lower().startswith("data:image/"):
        raise PrunerError("UNSUPPORTED_IMAGE", "The stored image URI is unsupported.", 422)
    parts = header[5:].split(";")
    mime_type = parts[0].lower()
    if mime_type == "image/jpg":
        mime_type = "image/jpeg"
    parameters = {part.lower() for part in parts[1:]}
    if "base64" not in parameters or mime_type not in SUPPORTED_IMAGE_MIMES:
        raise PrunerError("UNSUPPORTED_IMAGE", "The stored image type is unsupported.", 422)
    if not payload or len(payload) % 4 != 0:
        raise PrunerError("INVALID_IMAGE_DATA", "The stored image data is invalid.", 422)
    return mime_type, payload


def estimated_base64_size(payload: str) -> int:
    padding = len(payload) - len(payload.rstrip("="))
    return max(0, (len(payload) * 3) // 4 - padding)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def make_image_id(line_number: int, pointer: str, uri_digest: str) -> str:
    material = f"{line_number}:{pointer}:{uri_digest}".encode("ascii")
    return hashlib.sha256(material).hexdigest()


def image_dimensions(mime_type: str, payload: str) -> tuple[int | None, int | None]:
    prefix_length = min(len(payload), 256 * 1024)
    prefix_length -= prefix_length % 4
    if prefix_length <= 0:
        return None, None
    try:
        data = base64.b64decode(payload[:prefix_length], validate=True)
    except (binascii.Error, ValueError):
        return None, None

    try:
        if mime_type == "image/png" and data.startswith(b"\x89PNG\r\n\x1a\n") and len(data) >= 24:
            return struct.unpack(">II", data[16:24])
        if mime_type == "image/gif" and data[:6] in (b"GIF87a", b"GIF89a") and len(data) >= 10:
            return struct.unpack("<HH", data[6:10])
        if mime_type == "image/jpeg":
            return jpeg_dimensions(data)
        if mime_type == "image/webp":
            return webp_dimensions(data)
    except (IndexError, struct.error, ValueError):
        return None, None
    return None, None


def jpeg_dimensions(data: bytes) -> tuple[int | None, int | None]:
    if len(data) < 4 or data[:2] != b"\xff\xd8":
        return None, None
    index = 2
    sof_markers = {
        0xC0,
        0xC1,
        0xC2,
        0xC3,
        0xC5,
        0xC6,
        0xC7,
        0xC9,
        0xCA,
        0xCB,
        0xCD,
        0xCE,
        0xCF,
    }
    while index + 3 < len(data):
        if data[index] != 0xFF:
            index += 1
            continue
        while index < len(data) and data[index] == 0xFF:
            index += 1
        if index >= len(data):
            break
        marker = data[index]
        index += 1
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            continue
        if index + 2 > len(data):
            break
        segment_length = int.from_bytes(data[index : index + 2], "big")
        if segment_length < 2 or index + segment_length > len(data):
            break
        if marker in sof_markers and segment_length >= 7:
            height = int.from_bytes(data[index + 3 : index + 5], "big")
            width = int.from_bytes(data[index + 5 : index + 7], "big")
            return width, height
        index += segment_length
    return None, None


def webp_dimensions(data: bytes) -> tuple[int | None, int | None]:
    if len(data) < 30 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        return None, None
    chunk = data[12:16]
    if chunk == b"VP8X":
        width = 1 + int.from_bytes(data[24:27], "little")
        height = 1 + int.from_bytes(data[27:30], "little")
        return width, height
    if chunk == b"VP8 " and data[23:26] == b"\x9d\x01\x2a":
        width = int.from_bytes(data[26:28], "little") & 0x3FFF
        height = int.from_bytes(data[28:30], "little") & 0x3FFF
        return width, height
    if chunk == b"VP8L" and len(data) >= 25 and data[20] == 0x2F:
        bits = int.from_bytes(data[21:25], "little")
        width = (bits & 0x3FFF) + 1
        height = ((bits >> 14) & 0x3FFF) + 1
        return width, height
    return None, None


def read_line(path: Path, line_number: int) -> bytes:
    try:
        with path.open("rb") as handle:
            for current, raw_line in enumerate(handle, start=1):
                if current == line_number:
                    return raw_line
    except PermissionError as exc:
        raise PrunerError("PERMISSION_DENIED", "The conversation rollout cannot be read.", 403) from exc
    except OSError as exc:
        raise PrunerError("ROLLOUT_READ_ERROR", "The conversation rollout could not be read.", 500) from exc
    raise PrunerError("IMAGE_CHANGED", "The image line no longer exists.", 409)


def locate_image_item(raw_line: bytes, ref: ImageRef) -> dict[str, Any]:
    record = parse_json_line(raw_line, ref.line_number)
    payload = record.get("payload")
    if not isinstance(payload, dict):
        raise PrunerError("IMAGE_CHANGED", "The image no longer matches the scan.", 409)
    items = payload.get(ref.container)
    if not isinstance(items, list) or ref.index >= len(items):
        raise PrunerError("IMAGE_CHANGED", "The image no longer matches the scan.", 409)
    item = items[ref.index]
    if not isinstance(item, dict) or item.get("type") != "input_image":
        raise PrunerError("IMAGE_CHANGED", "The image no longer matches the scan.", 409)
    return item


def rewrite_line(
    raw_line: bytes,
    line_number: int,
    refs: list[ImageRef],
) -> tuple[bytes, set[str]]:
    record = parse_json_line(raw_line, line_number)
    payload = record.get("payload")
    if not isinstance(payload, dict):
        raise PrunerError("IMAGE_CHANGED", "A selected image no longer matches the scan.", 409)

    grouped: dict[str, list[ImageRef]] = {}
    for ref in refs:
        grouped.setdefault(ref.container, []).append(ref)
    found: set[str] = set()

    for container, container_refs in grouped.items():
        items = payload.get(container)
        if not isinstance(items, list):
            raise PrunerError("IMAGE_CHANGED", "A selected image no longer matches the scan.", 409)
        for ref in container_refs:
            if ref.index >= len(items):
                raise PrunerError("IMAGE_CHANGED", "A selected image no longer matches the scan.", 409)
            item = items[ref.index]
            if not isinstance(item, dict) or item.get("type") != "input_image":
                raise PrunerError("IMAGE_CHANGED", "A selected image no longer matches the scan.", 409)
            image_url = item.get("image_url")
            if not isinstance(image_url, str) or sha256_text(image_url) != ref.uri_sha256:
                raise PrunerError("IMAGE_CHANGED", "A selected image no longer matches the scan.", 409)
            expected_id = make_image_id(line_number, ref.pointer, ref.uri_sha256)
            if expected_id != ref.image_id:
                raise PrunerError("IMAGE_CHANGED", "A selected image no longer matches the scan.", 409)
            found.add(ref.image_id)
        for index in sorted((ref.index for ref in container_refs), reverse=True):
            del items[index]
        if not items:
            items.append({"type": "input_text", "text": PLACEHOLDER_TEXT})

    line_ending = b""
    if raw_line.endswith(b"\r\n"):
        line_ending = b"\r\n"
    elif raw_line.endswith(b"\n"):
        line_ending = b"\n"
    encoded = json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return encoded + line_ending, found


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
    except PermissionError as exc:
        raise PrunerError("PERMISSION_DENIED", "The conversation rollout cannot be read.", 403) from exc
    except OSError as exc:
        raise PrunerError("ROLLOUT_READ_ERROR", "The conversation rollout could not be read.", 500) from exc
    return digest.hexdigest(), size


def sha256_open_file(handle: Any) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    handle.flush()
    handle.seek(0)
    while True:
        chunk = handle.read(1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


def copy_path_to_open_file(source_path: Path, destination: Any) -> None:
    destination.seek(0)
    with source_path.open("rb") as source:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            destination.write(chunk)
    destination.truncate()
    destination.flush()
    os.fsync(destination.fileno())


def sync_directory(path: Path) -> None:
    if os.name == "nt" or not hasattr(os, "O_DIRECTORY"):
        return
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def unlink_quietly(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        LOGGER.warning("Could not remove temporary file: %s", path)
