from __future__ import annotations

import argparse
import hmac
import ipaddress
import json
import logging
import secrets
import threading
import time
import webbrowser
from collections import defaultdict, deque
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import urlopen

from pruner import PrunerError, SessionImagePruner


APP_VERSION = "1.0.0"
APP_NAME = "Codex 413 Fix"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
MAX_JSON_BODY = 64 * 1024

LOGGER = logging.getLogger("codex_image_pruner")

STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/vendor/lucide.js": ("vendor/lucide.js", "text/javascript; charset=utf-8"),
}


class SlidingWindowRateLimiter:
    RULES = {
        "bootstrap": (60, 60.0),
        "scan": (30, 60.0),
        "preview": (240, 60.0),
        "prune": (8, 60.0),
        "shutdown": (3, 60.0),
    }

    def __init__(self) -> None:
        self._events: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, client: str, action: str) -> float | None:
        limit, window = self.RULES[action]
        now = time.monotonic()
        cutoff = now - window
        key = (client, action)
        with self._lock:
            events = self._events[key]
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= limit:
                return max(0.1, window - (now - events[0]))
            events.append(now)
        return None


class ImagePrunerServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        pruner: SessionImagePruner,
        static_dir: Path,
    ) -> None:
        self.pruner = pruner
        self.static_dir = static_dir.resolve()
        self.csrf_token = secrets.token_urlsafe(32)
        self.rate_limiter = SlidingWindowRateLimiter()
        super().__init__(server_address, ImagePrunerHandler)


class ImagePrunerHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: ImagePrunerServer

    def version_string(self) -> str:
        return f"Codex413Fix/{APP_VERSION}"

    def log_message(self, format_string: str, *args: Any) -> None:
        path = urlsplit(self.path).path
        LOGGER.info("%s %s - %s", self.command, path, format_string % args)

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self'; connect-src 'self'; object-src 'none'; "
            "base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        )
        super().end_headers()

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_HEAD(self) -> None:
        self._dispatch("HEAD")

    def do_OPTIONS(self) -> None:
        self._dispatch("OPTIONS")

    def _dispatch(self, method: str) -> None:
        request_id = secrets.token_hex(12)
        try:
            self._validate_host()
            path = urlsplit(self.path).path
            if method == "GET":
                self._route_get(path)
                return
            if method == "POST":
                self._validate_origin()
                self._validate_csrf()
                self._route_post(path)
                return
            raise PrunerError("METHOD_NOT_ALLOWED", "Method not allowed.", 405)
        except PrunerError as exc:
            if method == "POST":
                self.close_connection = True
            self._send_error(exc, request_id)
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception:
            LOGGER.exception("Unhandled request error (%s)", request_id)
            self.close_connection = True
            self._send_error(
                PrunerError(
                    "INTERNAL_ERROR",
                    "The local tool encountered an unexpected error.",
                    500,
                ),
                request_id,
            )

    def _route_get(self, path: str) -> None:
        if path in STATIC_FILES:
            relative_path, content_type = STATIC_FILES[path]
            self._serve_static(relative_path, content_type)
            return
        if path == "/favicon.ico":
            self._send_bytes(204, b"", "image/x-icon")
            return
        if path == "/api/health":
            self._send_json(200, {"status": "ok", "version": APP_VERSION})
            return
        if path == "/api/bootstrap":
            self._check_rate_limit("bootstrap")
            self._send_json(
                200,
                {
                    "version": APP_VERSION,
                    "csrf_token": self.server.csrf_token,
                    "limits": {
                        "request_body_bytes": MAX_JSON_BODY,
                        "max_selection": 2000,
                    },
                },
            )
            return
        parts = path.split("/")
        if len(parts) == 5 and parts[1:3] == ["api", "image"]:
            self._serve_image(parts[3], parts[4])
            return
        raise PrunerError("NOT_FOUND", "Route not found.", 404)

    def _route_post(self, path: str) -> None:
        if path == "/api/scan":
            self._check_rate_limit("scan")
            body = self._read_json_body()
            require_exact_keys(body, {"thread_id"})
            thread_id = body.get("thread_id")
            if not isinstance(thread_id, str):
                raise PrunerError("INVALID_THREAD_ID", "Enter a valid conversation UUID.", 422)
            self._send_json(200, self.server.pruner.scan(thread_id))
            return
        if path == "/api/prune":
            self._check_rate_limit("prune")
            body = self._read_json_body()
            require_exact_keys(body, {"snapshot_id", "image_ids", "writer_stopped"})
            snapshot_id = body.get("snapshot_id")
            image_ids = body.get("image_ids")
            writer_stopped = body.get("writer_stopped")
            if not isinstance(snapshot_id, str):
                raise PrunerError("INVALID_SNAPSHOT_ID", "Invalid scan snapshot ID.", 422)
            if not isinstance(image_ids, list):
                raise PrunerError("INVALID_IMAGE_SELECTION", "The image selection is invalid.", 422)
            if not isinstance(writer_stopped, bool):
                raise PrunerError("WRITER_ACK_REQUIRED", "Confirm the writer state.", 422)
            result = self.server.pruner.prune(snapshot_id, image_ids, writer_stopped)
            self._send_json(200, result)
            return
        if path == "/api/shutdown":
            self._check_rate_limit("shutdown")
            body = self._read_json_body()
            require_exact_keys(body, set())
            self._send_json(200, {"status": "stopping"})
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return
        raise PrunerError("NOT_FOUND", "Route not found.", 404)

    def _serve_static(self, relative_path: str, content_type: str) -> None:
        path = (self.server.static_dir / relative_path).resolve()
        if path.parent != self.server.static_dir and self.server.static_dir not in path.parents:
            raise PrunerError("NOT_FOUND", "Static asset not found.", 404)
        try:
            payload = path.read_bytes()
        except FileNotFoundError as exc:
            raise PrunerError("NOT_FOUND", "Static asset not found.", 404) from exc
        except OSError as exc:
            raise PrunerError("STATIC_READ_ERROR", "Static asset could not be read.", 500) from exc
        self._send_bytes(200, payload, content_type)

    def _serve_image(self, snapshot_id: str, image_id: str) -> None:
        self._check_rate_limit("preview")
        payload, mime_type = self.server.pruner.get_image(snapshot_id, image_id)
        self._send_bytes(200, payload, mime_type)

    def _validate_host(self) -> None:
        raw_host = self.headers.get("Host")
        if not raw_host or len(raw_host) > 128:
            raise PrunerError("INVALID_HOST", "Invalid local Host header.", 403)
        try:
            parsed = urlsplit(f"//{raw_host}")
            hostname = (parsed.hostname or "").lower()
            port = parsed.port
        except ValueError as exc:
            raise PrunerError("INVALID_HOST", "Invalid local Host header.", 403) from exc
        if hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise PrunerError("INVALID_HOST", "Only loopback Host headers are accepted.", 403)
        if port != self.server.server_port:
            raise PrunerError("INVALID_HOST", "The Host port does not match this server.", 403)

    def _validate_origin(self) -> None:
        raw_origin = self.headers.get("Origin")
        if raw_origin is None:
            return
        if len(raw_origin) > 256:
            raise PrunerError("INVALID_ORIGIN", "Invalid request origin.", 403)
        try:
            parsed = urlsplit(raw_origin)
            hostname = (parsed.hostname or "").lower()
            port = parsed.port
        except ValueError as exc:
            raise PrunerError("INVALID_ORIGIN", "Invalid request origin.", 403) from exc
        if (
            parsed.scheme != "http"
            or hostname not in {"127.0.0.1", "localhost", "::1"}
            or port != self.server.server_port
        ):
            raise PrunerError("INVALID_ORIGIN", "Only this local origin may submit changes.", 403)

    def _validate_csrf(self) -> None:
        token = self.headers.get("X-CSRF-Token", "")
        if not token or not hmac.compare_digest(token, self.server.csrf_token):
            raise PrunerError("INVALID_CSRF", "The local request token is missing or invalid.", 403)

    def _check_rate_limit(self, action: str) -> None:
        client = self.client_address[0]
        retry_after = self.server.rate_limiter.check(client, action)
        if retry_after is not None:
            raise PrunerError(
                "RATE_LIMITED",
                "Too many local requests. Wait briefly and try again.",
                429,
                {"retry_after_seconds": max(1, int(retry_after + 0.999))},
            )

    def _read_json_body(self) -> dict[str, Any]:
        content_type = self.headers.get("Content-Type", "")
        if content_type.split(";", 1)[0].strip().lower() != "application/json":
            raise PrunerError("INVALID_CONTENT_TYPE", "Content-Type must be application/json.", 415)
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise PrunerError("LENGTH_REQUIRED", "Content-Length is required.", 411)
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise PrunerError("INVALID_CONTENT_LENGTH", "Invalid Content-Length.", 400) from exc
        if length <= 0:
            raise PrunerError("EMPTY_BODY", "A JSON request body is required.", 400)
        if length > MAX_JSON_BODY:
            raise PrunerError("REQUEST_TOO_LARGE", "The JSON request body is too large.", 413)
        raw_body = self.rfile.read(length)
        if len(raw_body) != length:
            raise PrunerError("INCOMPLETE_BODY", "The request body was incomplete.", 400)
        try:
            body = json.loads(raw_body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise PrunerError("INVALID_JSON", "The request body is not valid JSON.", 400) from exc
        if not isinstance(body, dict):
            raise PrunerError("INVALID_JSON", "The JSON request body must be an object.", 400)
        return body

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._send_bytes(status, encoded, "application/json; charset=utf-8")

    def _send_error(self, error: PrunerError, request_id: str) -> None:
        payload: dict[str, Any] = {
            "error": {
                "code": error.code,
                "message": error.message,
                "request_id": request_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        }
        if error.details:
            payload["error"]["details"] = error.details
        self._send_json(error.status, payload)

    def _send_bytes(self, status: int, payload: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if payload and self.command != "HEAD":
            self.wfile.write(payload)


def require_exact_keys(body: dict[str, Any], expected: set[str]) -> None:
    keys = set(body)
    if keys != expected:
        raise PrunerError(
            "INVALID_REQUEST_FIELDS",
            "The request contains missing or unexpected fields.",
            422,
        )


def validate_loopback_host(host: str) -> None:
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("The server host must be a loopback IP address.") from exc
    if not address.is_loopback:
        raise ValueError("The server may only bind to a loopback address.")


def build_server(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    pruner: SessionImagePruner | None = None,
    static_dir: Path | None = None,
) -> ImagePrunerServer:
    validate_loopback_host(host)
    if not 0 <= port <= 65535:
        raise ValueError("Port must be between 0 and 65535.")
    return ImagePrunerServer(
        (host, port),
        pruner or SessionImagePruner(),
        static_dir or Path(__file__).resolve().parent / "static",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Remove selected Codex image attachments that can trigger HTTP 413 errors."
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Loopback TCP port (default: 8765)")
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not open the local interface automatically.",
    )
    return parser.parse_args()


def existing_instance_is_healthy(url: str) -> bool:
    try:
        with urlopen(f"{url}api/health", timeout=1.0) as response:
            server_header = response.headers.get("Server", "")
            payload = json.load(response)
    except (HTTPError, URLError, OSError, ValueError, json.JSONDecodeError):
        return False
    return (
        response.status == 200
        and server_header.startswith("Codex413Fix/")
        and payload.get("status") == "ok"
    )


def main() -> None:
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    requested_url = f"http://127.0.0.1:{args.port}/"
    try:
        server = build_server(port=args.port)
    except OSError:
        if existing_instance_is_healthy(requested_url):
            if not args.no_browser:
                webbrowser.open(requested_url)
            return
        if args.port != DEFAULT_PORT:
            raise
        server = build_server(port=0)
    url = f"http://127.0.0.1:{server.server_port}/"
    print(f"{APP_NAME}: {url}", flush=True)
    print("Press Ctrl+C to stop.", flush=True)
    if not args.no_browser:
        threading.Timer(0.35, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("\nStopping...", flush=True)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
