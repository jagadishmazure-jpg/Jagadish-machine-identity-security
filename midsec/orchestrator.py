"""ReAct-style posture agent for machine identities.

Loop: scan inventory (via read-only views) -> score every identity ->
detect active threats -> propose remediations -> execute low-risk fixes
automatically, escalate high-risk ones for human confirmation. Every step
is written to the hash-chained audit log.
"""

from __future__ import annotations

import sqlite3

from . import itdr, pam, respond, sprawl, views
from .audit import AuditLog

AUTO_RISK = 0.3   # at or below: agent may act alone (rotation only)


class PostureAgent:
    def __init__(self, conn: sqlite3.Connection,
                 audit: AuditLog | None = None) -> None:
        self.conn = conn
        self.audit = audit or AuditLog()
        views.install_views(conn)

    def scan(self) -> list[dict]:
        """Step 1 (observe): posture of every active identity."""
        ranked = sprawl.remediation_list(self.conn)
        self.audit.record("agent.scan",
                          {"identities": len(ranked),
                           "worst": ranked[0]["id"] if ranked else None})
        return ranked

    def detect(self) -> list[dict]:
        """Step 2 (observe): active identity-threat signals."""
        findings = itdr.run_all(self.conn)
        self.audit.record("agent.detect",
                          {"findings": len(findings),
                           "signals": sorted({f["signal_id"]
                                              for f in findings})})
        return findings

    def plan(self, ranked: list[dict],
             findings: list[dict]) -> list[dict]:
        """Step 3 (think): ranked remediation proposals with actions."""
        proposals = []
        for scored in ranked:
            action = sprawl.recommended_action(scored)
            if action == "no action":
                continue
            auto = scored["risk"] <= AUTO_RISK and action.startswith(
                "force secret rotation")
            proposals.append({"identity_id": scored["id"],
                              "risk": scored["risk"],
                              "flags": scored["flags"],
                              "action": action,
                              "auto": auto})
        for f in findings:
            proposals.append({"identity_id": f["identity_id"],
                              "risk": 1.0 if f["severity"] == "critical"
                              else 0.8,
                              "flags": [f["signal_id"]],
                              "action": f"respond to {f['signal_id']}",
                              "auto": False,
                              "finding": f})
        proposals.sort(key=lambda p: (-p["risk"], str(p["identity_id"])))
        self.audit.record("agent.plan", {"proposals": len(proposals)})
        return proposals

    def act(self, proposals: list[dict], dry_run: bool = True) -> dict:
        """Step 4 (act): run auto fixes, escalate the rest. Fail-closed."""
        executed, escalated = [], []
        for p in proposals:
            if p["auto"]:
                r = respond.force_rotation(self.conn, p["identity_id"],
                                           dry_run=dry_run, audit=self.audit)
                executed.append({**p, "result": r})
            else:
                escalated.append(p)
                self.audit.record("agent.escalated", p)
        return {"executed": executed, "escalated": escalated,
                "dry_run": dry_run}

    def run(self, dry_run: bool = True) -> dict:
        ranked = self.scan()
        findings = self.detect()
        proposals = self.plan(ranked, findings)
        outcome = self.act(proposals, dry_run=dry_run)
        self.audit.record("agent.run_complete",
                          {"executed": len(outcome["executed"]),
                           "escalated": len(outcome["escalated"])})
        return {"ranked": ranked, "findings": findings,
                "proposals": proposals, **outcome}
