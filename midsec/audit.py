"""Hash-chained audit log (SHA-256, GENESIS-anchored, tamper-evident)."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditLog:
    def __init__(self) -> None:
        self.entries: list[dict] = []
        self._last = "GENESIS"

    def record(self, kind: str, detail: dict) -> dict:
        # AUDIT-COPY-01: store a JSON-safe copy so a caller changing its own
        # dict later cannot make an untampered chain fail verification.
        detail = json.loads(json.dumps(detail, sort_keys=True, default=str))
        at = _utcnow()
        payload = json.dumps({"kind": kind, "detail": detail,
                              "prev": self._last, "at": at},
                             sort_keys=True)
        digest = hashlib.sha256(payload.encode()).hexdigest()
        entry = {"seq": len(self.entries), "kind": kind, "detail": detail,
                 "prev": self._last, "at": at, "digest": digest}
        self.entries.append(entry)
        self._last = digest
        return entry

    def verify(self) -> bool:
        prev = "GENESIS"
        for e in self.entries:
            if e["prev"] != prev:
                return False
            payload = json.dumps({"kind": e["kind"], "detail": e["detail"],
                                  "prev": e["prev"], "at": e["at"]},
                                 sort_keys=True)
            if hashlib.sha256(payload.encode()).hexdigest() != e["digest"]:
                return False
            prev = e["digest"]
        return True

    def kinds(self, kind: str) -> list[dict]:
        return [e for e in self.entries if e["kind"] == kind]
