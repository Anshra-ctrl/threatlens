"""ThreatLens web server. Run:  python app.py  [port]

Serves the dashboard and a tiny JSON API. Standard library only.
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from detector import analyze, generate_sample

BASE_DIR = Path(__file__).resolve().parent
INDEX_FILE = BASE_DIR / "static" / "index.html"
MAX_BODY_BYTES = 5 * 1024 * 1024  # 5 MB of log text


class Handler(BaseHTTPRequestHandler):
    """Handles requests for the dashboard page and the JSON API."""

    server_version = "ThreatLens/1.0"

    def _send(self, status, body, content_type):
        """Send a complete response with a few safe default headers."""
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, status, payload):
        """Send a JSON response."""
        self._send(status, json.dumps(payload), "application/json; charset=utf-8")

    def do_GET(self):  # pylint: disable=invalid-name  # name required by http.server
        """Serve the dashboard (/) and the sample logs (/api/sample)."""
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._send(200, INDEX_FILE.read_bytes(), "text/html; charset=utf-8")
        elif path == "/api/sample":
            self._send(200, generate_sample(), "text/plain; charset=utf-8")
        else:
            self._json(404, {"error": "Not found."})

    def do_POST(self):  # pylint: disable=invalid-name  # name required by http.server
        """Analyze the log text sent to /api/analyze."""
        if self.path.split("?", 1)[0] != "/api/analyze":
            self._json(404, {"error": "Not found."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length <= 0:
            self._json(400, {"error": "Send the log text in the request body."})
            return
        if length > MAX_BODY_BYTES:
            self._json(413, {"error": "Log is too large. The limit is 5 MB."})
            return
        text = self.rfile.read(length).decode("utf-8", errors="replace")
        try:
            report = analyze(text)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # Deliberately broad: keep the server alive on unexpected input.
            self._json(500, {"error": f"Analysis failed: {exc}"})
            return
        self._json(200, report)


def main():
    """Start the web server on the chosen port (default 8000)."""
    port = 8000
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    elif os.environ.get("PORT"):
        port = int(os.environ["PORT"])
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"ThreatLens is running at http://127.0.0.1:{port}  (press Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
