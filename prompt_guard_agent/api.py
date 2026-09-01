"""实时 HTTP 接口：POST /v1/guard/analyze 或 /v1/guard/batch。"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

try:
    from .prompt_guard import PromptInjectionGuard
except ImportError:  # python api.py
    from prompt_guard import PromptInjectionGuard

MAX_BODY_SIZE = 2 * 1024 * 1024
GUARD = PromptInjectionGuard()


class Handler(BaseHTTPRequestHandler):
    def _reply(self, code: int, body: dict[str, Any]) -> None:
        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self) -> None:  # noqa: N802
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1:
                raise ValueError("request body is required")
            if length > MAX_BODY_SIZE:
                self._reply(413, {"error": "payload too large", "max_bytes": MAX_BODY_SIZE})
                return
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if self.path == "/v1/guard/analyze":
                if isinstance(payload, dict) and "record" in payload:
                    data = payload["record"]
                elif isinstance(payload, dict) and set(payload) == {"data"}:
                    # 兼容 v0.x 请求格式；新客户端建议使用 {"record": ...}。
                    data = payload["data"]
                else:
                    data = payload
                self._reply(200, GUARD.analyze(data).to_dict())
            elif self.path == "/v1/guard/batch":
                records = payload.get("records") if isinstance(payload, dict) else payload
                if not isinstance(records, list):
                    raise ValueError("records must be an array")
                self._reply(200, {"results": [GUARD.analyze(item).to_dict() for item in records]})
            else:
                self._reply(404, {"error": "not found"})
        except (ValueError, json.JSONDecodeError) as exc:
            self._reply(400, {"error": str(exc)})
        except Exception:
            self._reply(500, {"error": "internal error"})

    def log_message(self, *_: Any) -> None:
        return


def serve(host: str = "0.0.0.0", port: int = 8000) -> None:
    print(f"Prompt guard listening on http://{host}:{port}")
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    serve()
