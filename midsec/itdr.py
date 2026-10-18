"""Identity threat detection for non-human identities.

Signals (each finding cites its signal ID):
- SIG-GEO-01: activity from a country never seen before for this identity.
- SIG-TRAVEL-01: impossible travel — two cities too far apart, too close
  together in time for a single credential to have moved.
- SIG-SPIKE-01: usage volume far above the identity's own baseline.
- SIG-REUSE-01: the same token fingerprint used by two identities.
"""

from __future__ import annotations

import math
import sqlite3
from datetime import datetime

# Fictional-but-plausible city coordinates for travel math.
_CITIES = {
    "Chicago": (41.88, -87.63),
    "Frankfurt": (50.11, 8.68),
    "Lagos": (6.52, 3.37),
    "Singapore": (1.35, 103.82),
}

TRAVEL_SPEED_KMH = 1000.0   # above this between two events: impossible
SPIKE_MULTIPLE = 5.0        # above this vs baseline: spike


def _haversine_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    lat1, lon1, lat2, lon2 = map(math.radians, (*a, *b))
    dlat, dlon = lat2 - lat1, lon2 - lon1
    h = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * \
        math.sin(dlon / 2) ** 2
    return 6371.0 * 2 * math.asin(math.sqrt(h))


def detect_first_seen_geo(conn: sqlite3.Connection) -> list[dict]:
    """SIG-GEO-01: a country with no history for the identity."""
    findings = []
    ids = [r["id"] for r in conn.execute("SELECT id FROM identities")]
    for ident in ids:
        first = conn.execute(
            "SELECT country, MIN(ts) AS first_seen FROM usage_events"
            " WHERE identity_id=? GROUP BY country ORDER BY first_seen",
            (ident,)).fetchall()
        if len(first) < 2:
            continue
        # Deterministic rule: any country beyond the very first one ever
        # seen is a first-seen-geo finding (one per identity).
        seen_first = first[0]["country"]
        r = first[1]
        findings.append({
            "signal_id": "SIG-GEO-01",
            "identity_id": ident,
            "severity": "high",
            "detail": f"first activity from {r['country']} at"
                      f" {r['first_seen']} (baseline: {seen_first})",
        })
    return findings


def detect_impossible_travel(conn: sqlite3.Connection) -> list[dict]:
    """SIG-TRAVEL-01: two events too far apart in space, too close in time."""
    findings = []
    ids = [r["id"] for r in conn.execute("SELECT id FROM identities")]
    for ident in ids:
        rows = conn.execute(
            "SELECT ts, city FROM usage_events WHERE identity_id=?"
            " AND city IS NOT NULL ORDER BY ts", (ident,)).fetchall()
        for prev, cur in zip(rows, rows[1:]):
            a, b = _CITIES.get(prev["city"]), _CITIES.get(cur["city"])
            if not a or not b or prev["city"] == cur["city"]:
                continue
            t1 = datetime.fromisoformat(prev["ts"])
            t2 = datetime.fromisoformat(cur["ts"])
            hours = max((t2 - t1).total_seconds() / 3600.0, 1e-6)
            speed = _haversine_km(a, b) / hours
            if speed > TRAVEL_SPEED_KMH:
                findings.append({
                    "signal_id": "SIG-TRAVEL-01",
                    "identity_id": ident,
                    "severity": "critical",
                    "detail": f"{prev['city']} -> {cur['city']} in"
                              f" {hours:.2f}h implies {speed:,.0f} km/h",
                })
                break
    return findings


def detect_usage_spike(conn: sqlite3.Connection) -> list[dict]:
    """SIG-SPIKE-01: a day's volume far above the identity's baseline."""
    findings = []
    ids = [r["id"] for r in conn.execute("SELECT id FROM identities")]
    for ident in ids:
        days = conn.execute(
            "SELECT substr(ts,1,10) AS day, COUNT(*) AS n FROM usage_events"
            " WHERE identity_id=? GROUP BY day ORDER BY day", (ident,)).fetchall()
        if len(days) < 3:
            continue
        baseline = sum(d["n"] for d in days[:-1]) / max(len(days) - 1, 1)
        last = days[-1]
        if baseline > 0 and last["n"] >= baseline * SPIKE_MULTIPLE:
            findings.append({
                "signal_id": "SIG-SPIKE-01",
                "identity_id": ident,
                "severity": "high",
                "detail": f"{last['n']} events on {last['day']} vs baseline"
                          f" {baseline:.1f}/day",
            })
    return findings


def detect_token_reuse(conn: sqlite3.Connection) -> list[dict]:
    """SIG-REUSE-01: one token fingerprint active on two identities."""
    rows = conn.execute(
        "SELECT token_fp, COUNT(DISTINCT identity_id) AS n,"
        " GROUP_CONCAT(DISTINCT identity_id) AS ids"
        " FROM usage_events WHERE token_fp IS NOT NULL"
        " GROUP BY token_fp HAVING n > 1").fetchall()
    return [{
        "signal_id": "SIG-REUSE-01",
        "identity_id": r["ids"],
        "identity_ids": sorted(r["ids"].split(",")),
        "severity": "critical",
        "detail": f"token {r['token_fp']} used by {r['ids']}",
    } for r in rows]


def run_all(conn: sqlite3.Connection) -> list[dict]:
    findings = []
    findings += detect_first_seen_geo(conn)
    findings += detect_impossible_travel(conn)
    findings += detect_usage_spike(conn)
    findings += detect_token_reuse(conn)
    return findings
