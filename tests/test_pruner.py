from __future__ import annotations

import base64
import http.client
import json
import logging
import os
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]

import sys

sys.path.insert(0, str(PROJECT_ROOT))

from app import build_server  # noqa: E402
from pruner import PLACEHOLDER_TEXT, PrunerError, SessionImagePruner  # noqa: E402


THREAD_ID = "019fb63c-14d7-7bf2-b4fe-fa24e22100fd"
PNG_1X1 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Wl6Z9sAAAAASUVORK5CYII="
GIF_1X1 = "R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw=="


def input_image(mime_type: str, payload: str) -> dict[str, str]:
    return {
        "type": "input_image",
        "image_url": f"data:{mime_type};base64,{payload}",
        "detail": "auto",
    }


def encode_line(record: dict, ending: bytes = b"\n", spaced: bool = False) -> bytes:
    separators = None if spaced else (",", ":")
    return json.dumps(record, ensure_ascii=False, separators=separators).encode("utf-8") + ending


class Fixture:
    def __init__(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.codex_home = self.root / ".codex"
        self.sessions = self.codex_home / "sessions"
        self.sessions.mkdir(parents=True)
        self.rollout = self.sessions / f"rollout-{THREAD_ID}.jsonl"
        self.db = self.codex_home / "state_5.sqlite"
        self.lines = self._write_rollout()
        self._write_db(self.rollout)
        self.pruner = SessionImagePruner(
            codex_home=self.codex_home,
            state_db=self.db,
            trusted_roots=[self.sessions],
            snapshot_ttl_seconds=300,
        )

    def close(self) -> None:
        self.tempdir.cleanup()

    def _write_rollout(self) -> list[bytes]:
        records = [
            encode_line(
                {
                    "timestamp": "2026-07-31T04:00:00.000Z",
                    "type": "session_meta",
                    "payload": {"id": THREAD_ID, "cwd": "C:\\work"},
                },
                ending=b"\r\n",
                spaced=True,
            ),
            encode_line(
                {
                    "timestamp": "2026-07-31T04:01:00.000Z",
                    "type": "response_item",
                    "payload": {
                        "type": "message",
                        "role": "user",
                        "content": [
                            {"type": "input_text", "text": "keep this user text"},
                            input_image("image/png", PNG_1X1),
                            input_image("image/gif", GIF_1X1),
                        ],
                    },
                }
            ),
            encode_line(
                {
                    "timestamp": "2026-07-31T04:02:00.000Z",
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call_output",
                        "call_id": "safe-test-call",
                        "output": [
                            {"type": "input_text", "text": "screenshot path omitted"},
                            input_image("image/png", PNG_1X1),
                        ],
                    },
                }
            ),
            encode_line(
                {
                    "timestamp": "2026-07-31T04:03:00.000Z",
                    "type": "response_item",
                    "payload": {
                        "type": "synthetic_other",
                        "output": [input_image("image/gif", GIF_1X1)],
                    },
                }
            ),
            encode_line(
                {
                    "timestamp": "2026-07-31T04:04:00.000Z",
                    "type": "event_msg",
                    "payload": {"type": "token_count", "safe": True},
                },
                spaced=True,
            ),
        ]
        self.rollout.write_bytes(b"".join(records))
        return records

    def _write_db(self, rollout_path: Path) -> None:
        connection = sqlite3.connect(self.db)
        try:
            connection.execute(
                """
                CREATE TABLE threads (
                    id TEXT PRIMARY KEY,
                    rollout_path TEXT NOT NULL,
                    title TEXT NOT NULL,
                    cwd TEXT NOT NULL,
                    source TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                )
                """
            )
            connection.execute(
                """
                INSERT INTO threads
                    (id, rollout_path, title, cwd, source, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    THREAD_ID,
                    str(rollout_path),
                    "Synthetic image test",
                    str(self.root / "project"),
                    "app",
                    1_753_937_200,
                    1_753_937_400,
                ),
            )
            connection.commit()
        finally:
            connection.close()


class SessionImagePrunerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Fixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_scan_lists_images_without_leaking_data_uris(self) -> None:
        result = self.fixture.pruner.scan(THREAD_ID)

        self.assertEqual(result["summary"]["image_count"], 4)
        self.assertEqual(result["summary"]["source_counts"], {"user": 2, "tool": 1, "other": 1})
        self.assertLessEqual(len(result["thread"]["title"]), 180)
        self.assertEqual([image["line_number"] for image in result["images"]], [2, 2, 3, 4])
        self.assertEqual(result["images"][0]["width"], 1)
        self.assertEqual(result["images"][0]["height"], 1)
        self.assertEqual(result["images"][1]["width"], 1)
        self.assertEqual(result["images"][1]["height"], 1)
        serialized = json.dumps(result)
        self.assertNotIn("data:image", serialized)
        self.assertNotIn(PNG_1X1, serialized)
        self.assertNotIn("keep this user text", serialized)

    def test_preview_decodes_only_scanned_image(self) -> None:
        scan = self.fixture.pruner.scan(THREAD_ID)
        first = scan["images"][0]

        payload, mime_type = self.fixture.pruner.get_image(scan["snapshot_id"], first["id"])

        self.assertEqual(mime_type, "image/png")
        self.assertEqual(payload, base64.b64decode(PNG_1X1))
        with self.assertRaises(PrunerError) as context:
            self.fixture.pruner.get_image(scan["snapshot_id"], "0" * 64)
        self.assertEqual(context.exception.code, "IMAGE_NOT_FOUND")

    def test_selective_prune_creates_exact_backup_and_preserves_other_lines(self) -> None:
        original = self.fixture.rollout.read_bytes()
        original_lines = original.splitlines(keepends=True)
        scan = self.fixture.pruner.scan(THREAD_ID)
        selected = next(image for image in scan["images"] if image["source"] == "user" and image["mime_type"] == "image/png")

        result = self.fixture.pruner.prune(scan["snapshot_id"], [selected["id"]], True)

        backup_path = Path(result["backup_path"])
        self.assertTrue(backup_path.is_file())
        self.assertEqual(backup_path.read_bytes(), original)
        rewritten_lines = self.fixture.rollout.read_bytes().splitlines(keepends=True)
        self.assertEqual(rewritten_lines[0], original_lines[0])
        self.assertEqual(rewritten_lines[2], original_lines[2])
        self.assertEqual(rewritten_lines[3], original_lines[3])
        self.assertEqual(rewritten_lines[4], original_lines[4])

        changed = json.loads(rewritten_lines[1])
        content = changed["payload"]["content"]
        self.assertEqual([item["type"] for item in content], ["input_text", "input_image"])
        self.assertEqual(content[0]["text"], "keep this user text")
        self.assertEqual(content[1]["image_url"], f"data:image/gif;base64,{GIF_1X1}")
        self.assertEqual(result["removed_count"], 1)
        self.assertGreater(result["freed_file_bytes"], 0)

        audit = self.fixture.pruner.audit_path.read_text(encoding="utf-8")
        self.assertIn('"event":"prune_requested"', audit)
        self.assertIn('"event":"prune_succeeded"', audit)
        self.assertNotIn("data:image", audit)
        self.assertNotIn(PNG_1X1, audit)

    def test_multiple_deletions_use_descending_indices(self) -> None:
        scan = self.fixture.pruner.scan(THREAD_ID)
        selected = [image["id"] for image in scan["images"] if image["source"] == "user"]

        self.fixture.pruner.prune(scan["snapshot_id"], selected, True)

        record = json.loads(self.fixture.rollout.read_bytes().splitlines()[1])
        self.assertEqual(record["payload"]["content"], [{"type": "input_text", "text": "keep this user text"}])

    def test_image_only_parent_gets_text_placeholder(self) -> None:
        scan = self.fixture.pruner.scan(THREAD_ID)
        selected = next(image for image in scan["images"] if image["source"] == "other")

        self.fixture.pruner.prune(scan["snapshot_id"], [selected["id"]], True)

        record = json.loads(self.fixture.rollout.read_bytes().splitlines()[3])
        self.assertEqual(
            record["payload"]["output"],
            [{"type": "input_text", "text": PLACEHOLDER_TEXT}],
        )

    def test_stale_snapshot_never_mutates_file(self) -> None:
        scan = self.fixture.pruner.scan(THREAD_ID)
        selected_id = scan["images"][0]["id"]
        appended = encode_line({"timestamp": "later", "payload": {"type": "event"}})
        with self.fixture.rollout.open("ab") as handle:
            handle.write(appended)
        changed = self.fixture.rollout.read_bytes()

        with self.assertRaises(PrunerError) as context:
            self.fixture.pruner.prune(scan["snapshot_id"], [selected_id], True)

        self.assertEqual(context.exception.code, "SNAPSHOT_STALE")
        self.assertEqual(self.fixture.rollout.read_bytes(), changed)
        self.assertFalse(self.fixture.pruner.backup_root.exists())

    def test_writer_acknowledgement_is_required(self) -> None:
        scan = self.fixture.pruner.scan(THREAD_ID)
        with self.assertRaises(PrunerError) as context:
            self.fixture.pruner.prune(scan["snapshot_id"], [scan["images"][0]["id"]], False)
        self.assertEqual(context.exception.code, "WRITER_ACK_REQUIRED")

    @unittest.skipUnless(os.name == "nt", "Windows handle fallback")
    def test_windows_locked_in_place_fallback(self) -> None:
        scan = self.fixture.pruner.scan(THREAD_ID)
        selected_id = scan["images"][0]["id"]
        original = self.fixture.rollout.read_bytes()
        real_replace = os.replace

        def replace_with_locked_target(source, destination):
            if Path(destination).suffix.lower() == ".jsonl":
                raise PermissionError(13, "simulated sharing violation", str(destination))
            return real_replace(source, destination)

        with mock.patch("pruner.os.replace", side_effect=replace_with_locked_target):
            result = self.fixture.pruner.prune(scan["snapshot_id"], [selected_id], True)

        self.assertEqual(result["install_mode"], "locked_in_place")
        self.assertEqual(Path(result["backup_path"]).read_bytes(), original)
        rescanned = self.fixture.pruner.scan(THREAD_ID)
        self.assertEqual(rescanned["summary"]["image_count"], 3)

    def test_untrusted_indexed_rollout_is_rejected(self) -> None:
        outside = self.fixture.root / "outside.jsonl"
        outside.write_bytes(self.fixture.rollout.read_bytes())
        connection = sqlite3.connect(self.fixture.db)
        try:
            connection.execute("UPDATE threads SET rollout_path = ? WHERE id = ?", (str(outside), THREAD_ID))
            connection.commit()
        finally:
            connection.close()

        with self.assertRaises(PrunerError) as context:
            self.fixture.pruner.scan(THREAD_ID)
        self.assertEqual(context.exception.code, "UNTRUSTED_ROLLOUT_PATH")

    @unittest.skipUnless(os.name == "nt", "Windows extended path prefix")
    def test_windows_extended_length_rollout_path_is_trusted(self) -> None:
        extended_path = "\\\\?\\" + str(self.fixture.rollout.resolve())
        connection = sqlite3.connect(self.fixture.db)
        try:
            connection.execute(
                "UPDATE threads SET rollout_path = ? WHERE id = ?",
                (extended_path, THREAD_ID),
            )
            connection.commit()
        finally:
            connection.close()

        result = self.fixture.pruner.scan(THREAD_ID)
        self.assertEqual(result["summary"]["image_count"], 4)

    def test_invalid_jsonl_fails_without_exposing_line_content(self) -> None:
        self.fixture.rollout.write_bytes(b'{"valid":true}\nnot-secret-but-invalid\n')
        with self.assertRaises(PrunerError) as context:
            self.fixture.pruner.scan(THREAD_ID)
        self.assertEqual(context.exception.code, "INVALID_JSONL")
        self.assertIn("line 2", context.exception.message)
        self.assertNotIn("not-secret", context.exception.message)


class HttpApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Fixture()
        logging.getLogger("codex_image_pruner").setLevel(logging.CRITICAL)
        self.server = build_server(
            port=0,
            pruner=self.fixture.pruner,
            static_dir=PROJECT_ROOT / "static",
        )
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.fixture.close()

    def request(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        request_headers = dict(headers or {})
        encoded = None
        if body is not None:
            encoded = json.dumps(body).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        connection.request(method, path, body=encoded, headers=request_headers)
        response = connection.getresponse()
        payload = response.read()
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        status = response.status
        connection.close()
        return status, response_headers, payload

    def bootstrap(self) -> tuple[str, dict[str, str]]:
        status, headers, payload = self.request("GET", "/api/bootstrap")
        self.assertEqual(status, 200)
        return json.loads(payload)["csrf_token"], headers

    def test_bootstrap_has_security_headers_and_static_page(self) -> None:
        token, headers = self.bootstrap()
        self.assertTrue(token)
        self.assertIn("default-src 'self'", headers["content-security-policy"])
        self.assertEqual(headers["x-content-type-options"], "nosniff")
        self.assertEqual(headers["x-frame-options"], "DENY")
        self.assertEqual(headers["cross-origin-resource-policy"], "same-origin")

        status, page_headers, payload = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertTrue(page_headers["content-type"].startswith("text/html"))
        self.assertIn("Codex 413 Fix", payload.decode("utf-8"))

    def test_post_requires_csrf_and_valid_host(self) -> None:
        body = {"thread_id": THREAD_ID}
        status, _, payload = self.request("POST", "/api/scan", body)
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(payload)["error"]["code"], "INVALID_CSRF")

        token, _ = self.bootstrap()
        status, _, payload = self.request(
            "POST",
            "/api/scan",
            body,
            {"X-CSRF-Token": token, "Host": f"malicious.test:{self.port}"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(payload)["error"]["code"], "INVALID_HOST")

    def test_scan_preview_and_validation_flow(self) -> None:
        token, _ = self.bootstrap()
        headers = {"X-CSRF-Token": token}
        status, _, payload = self.request("POST", "/api/scan", {"thread_id": THREAD_ID}, headers)
        self.assertEqual(status, 200)
        scan = json.loads(payload)
        self.assertEqual(scan["summary"]["image_count"], 4)

        status, image_headers, image_payload = self.request("GET", scan["images"][0]["preview_url"])
        self.assertEqual(status, 200)
        self.assertEqual(image_headers["content-type"], "image/png")
        self.assertEqual(image_payload, base64.b64decode(PNG_1X1))

        status, _, error_payload = self.request(
            "POST",
            "/api/prune",
            {
                "snapshot_id": scan["snapshot_id"],
                "image_ids": [scan["images"][0]["id"]],
                "writer_stopped": False,
            },
            headers,
        )
        self.assertEqual(status, 422)
        self.assertEqual(json.loads(error_payload)["error"]["code"], "WRITER_ACK_REQUIRED")

    def test_http_prune_and_rescan_main_flow(self) -> None:
        token, _ = self.bootstrap()
        headers = {"X-CSRF-Token": token}
        status, _, payload = self.request("POST", "/api/scan", {"thread_id": THREAD_ID}, headers)
        self.assertEqual(status, 200)
        scan = json.loads(payload)

        status, _, payload = self.request(
            "POST",
            "/api/prune",
            {
                "snapshot_id": scan["snapshot_id"],
                "image_ids": [scan["images"][0]["id"]],
                "writer_stopped": True,
            },
            headers,
        )
        self.assertEqual(status, 200)
        result = json.loads(payload)
        self.assertEqual(result["removed_count"], 1)
        self.assertTrue(Path(result["backup_path"]).is_file())

        status, _, payload = self.request("POST", "/api/scan", {"thread_id": THREAD_ID}, headers)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["summary"]["image_count"], 3)

    def test_oversized_json_body_is_rejected(self) -> None:
        token, _ = self.bootstrap()
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        oversized = b"{" + (b" " * (64 * 1024)) + b"}"
        connection.request(
            "POST",
            "/api/scan",
            body=oversized,
            headers={
                "Content-Type": "application/json",
                "X-CSRF-Token": token,
            },
        )
        response = connection.getresponse()
        payload = response.read()
        connection.close()
        self.assertEqual(response.status, 413)
        self.assertEqual(json.loads(payload)["error"]["code"], "REQUEST_TOO_LARGE")

    def test_wrong_origin_and_unknown_fields_are_rejected(self) -> None:
        token, _ = self.bootstrap()
        status, _, payload = self.request(
            "POST",
            "/api/scan",
            {"thread_id": THREAD_ID},
            {"X-CSRF-Token": token, "Origin": "http://example.invalid"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(payload)["error"]["code"], "INVALID_ORIGIN")

        status, _, payload = self.request(
            "POST",
            "/api/scan",
            {"thread_id": THREAD_ID, "path": "C:\\secret"},
            {"X-CSRF-Token": token},
        )
        self.assertEqual(status, 422)
        self.assertEqual(json.loads(payload)["error"]["code"], "INVALID_REQUEST_FIELDS")

    def test_shutdown_requires_csrf_and_stops_server(self) -> None:
        status, _, payload = self.request("POST", "/api/shutdown", {})
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(payload)["error"]["code"], "INVALID_CSRF")

        token, _ = self.bootstrap()
        status, _, payload = self.request(
            "POST",
            "/api/shutdown",
            {},
            {"X-CSRF-Token": token},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["status"], "stopping")
        self.thread.join(timeout=3)
        self.assertFalse(self.thread.is_alive())


if __name__ == "__main__":
    unittest.main()
