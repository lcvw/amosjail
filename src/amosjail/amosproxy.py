"""amosjaild's side of amosproxy's control socket (PLAN M2).

Tagging happens in amosjail-enter, from inside the jail's new audit
session, because amosproxy tags the caller's own session. The daemon checks
the reply, untags at teardown, and keeps `[amosproxy] exempt` applied.
"""

from __future__ import annotations

import json
import logging
import os
import socket

from amosjail._vendor import protocol
from amosjail.config import AmosproxySettings

logger = logging.getLogger(__name__)


class AmosproxyError(RuntimeError):
    pass


def request(path: str, msg: dict, timeout: float = 10.0) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect(path)
        except OSError as e:
            raise AmosproxyError(f"amosproxy isn't running ({path}: {e.strerror})") from None
        s.sendall(protocol.encode(msg))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                raise AmosproxyError("amosproxy closed the connection")
            buf += chunk
    reply = protocol.decode(buf)
    if not reply.get("ok"):
        raise AmosproxyError(f"amosproxy: {reply.get('error')}")
    return reply


def check_tag_reply(line: str, asid: int, settings: AmosproxySettings) -> None:
    """The reply amosjail-enter got to its "tag" request."""
    try:
        reply = json.loads(line)
    except ValueError:
        raise AmosproxyError(f"amosproxy sent {line[:200]!r}") from None
    if not isinstance(reply, dict) or not reply.get("ok"):
        raise AmosproxyError(f"tag refused: {reply.get('error') if isinstance(reply, dict) else reply}")
    if reply.get("asid") != asid:
        raise AmosproxyError(f"amosproxy tagged asid {reply.get('asid')}, expected {asid}")
    ca = reply.get("ca")
    if isinstance(ca, dict) and ca != settings.ca_paths():
        raise AmosproxyError(f"amosproxy publishes its CA at {ca}, config says {settings.ca_paths()}")


def untag(settings: AmosproxySettings, asid: int) -> None:
    try:
        request(settings.socket, {"op": "untag", "asid": asid})
    except AmosproxyError as e:
        # Down or already untagged: amosproxy's own session GC drops tags
        # of empty sessions anyway.
        logger.info("untag asid %d: %s", asid, e)


def exempt_file(state_dir: str) -> str:
    return os.path.join(state_dir, "amosproxy-exempt.conf")


def write_exempt_file(settings: AmosproxySettings, state_dir: str) -> str:
    path = exempt_file(state_dir)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write("# written by amosjail from [amosproxy] exempt\n")
        f.writelines(r + "\n" for r in settings.exempt)
    os.replace(tmp, path)
    return path


def reconcile_exemptions(settings: AmosproxySettings, state_dir: str) -> None:
    """Make amosproxy's exemptions include the config's, and drop the ones
    amosjail added earlier that the config no longer lists. Rules added by
    hand with `amosproxy exempt add` are left alone."""
    applied_path = os.path.join(state_dir, "exempt-applied.json")
    try:
        with open(applied_path) as f:
            applied = set(json.load(f))
    except (OSError, ValueError):
        applied = set()
    want = set(settings.exempt)
    if not want and not applied:
        return
    write_exempt_file(settings, state_dir)
    if want:
        request(settings.socket, {"op": "exempt_add", "rules": sorted(want)})
    gone = applied - want
    if gone:
        request(settings.socket, {"op": "exempt_remove", "rules": sorted(gone)})
    with open(applied_path, "w") as f:
        json.dump(sorted(want), f)
