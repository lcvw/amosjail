"""Control-socket wire format: one JSON object per line, request then reply.

Requests:  {"op": "tag", "label": str | None}
           {"op": "status"}
           {"op": "untag", "pid": int}            (root only)
Replies:   {"ok": true, ...} | {"ok": false, "error": str}

The daemon never trusts a pid from the request body for "tag": it tags the
peer pid reported by the kernel (LOCAL_PEERPID), so a caller can only ever
restrict itself.
"""

from __future__ import annotations

import json

SOCKET_PATH = "/var/run/amosproxy.sock"
MAX_LINE = 64 * 1024


def encode(msg: dict) -> bytes:
    return json.dumps(msg, separators=(",", ":")).encode() + b"\n"


def decode(line: bytes) -> dict:
    msg = json.loads(line)
    if not isinstance(msg, dict):
        raise ValueError("message must be a JSON object")
    return msg
