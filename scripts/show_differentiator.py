"""Print what this repo does that the posture scanner and auth repos do not:
time-boxed elevation behind a separation-of-duties gate, runtime threat
signals from usage events, and a confirmation-gated response playbook."""

import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from midsec import itdr, pam, respond, views  # noqa: E402
from midsec.inventory import connect  # noqa: E402
from midsec.orchestrator import PostureAgent  # noqa: E402

T0 = datetime(2026, 10, 18, 9, 0, tzinfo=timezone.utc)
conn = connect()
views.install_views(conn)

run = PostureAgent(conn).run(dry_run=True)
worst = run["ranked"][0]
print(f"worst identity: {worst['id']} risk={worst['risk']} flags={worst['flags']}")
print("runtime signals:", dict(sorted(Counter(f["signal_id"] for f in run["findings"]).items())))
print(f"proposals: {len(run['proposals'])} -> auto {len(run['executed'])}, "
      f"escalated {len(run['escalated'])} (dry run)")

try:
    pam.request_elevation(conn, "svc-etl-legacy", "ex-chen", now=T0)
except pam.ElevationError as err:
    print(f"elevation requested by departed owner ex-chen: refused ({str(err).split(':')[0]})")
e = pam.request_elevation(conn, "svc-etl-legacy", "data-oncall", now=T0)
print(f"elevation svc-etl-legacy: risk={e['risk']} status={e['status']}")
for who in ("data-oncall", "sec-oncall"):
    try:
        print(f"  confirm by {who}: {pam.confirm_elevation(conn, e['id'], who, now=T0)['status']}")
    except pam.ElevationError as err:
        print(f"  confirm by {who}: refused ({str(err).split(':')[0]})")
try:
    pam.request_elevation(conn, "key-webhook", "team-platform", duration_h=72, now=T0)
except pam.ElevationError as err:
    print(f"72h elevation: refused ({str(err).split(':')[0]})")

reuse = next(f for f in itdr.run_all(conn) if f["signal_id"] == "SIG-REUSE-01")
try:
    respond.respond_to_finding(conn, reuse)
except respond.ConfirmationRequired as err:
    print(f"token reuse on {reuse['identity_ids']}: {str(err).split(':')[0]} until a human confirms")
out = respond.respond_to_finding(conn, reuse, confirmed=True, dry_run=True)
print(f"  confirmed (dry run): revoke {[r['identity_id'] for r in out['results']]}")
