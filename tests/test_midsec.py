"""Regression checks for machine-identity security (deterministic)."""

import sqlite3
from datetime import datetime, timezone

import pytest

from midsec import audit, demo_helpers, feedback, itdr, pam, respond, sprawl, views
from midsec.audit import AuditLog
from midsec.inventory import TODAY, connect
from midsec.orchestrator import PostureAgent
from midsec.views import GatewayDenied, run_query_authorizer_only


@pytest.fixture()
def conn():
    c = connect()
    views.install_views(c)
    yield c
    c.close()


# ---------- inventory ----------

def test_seed_loads_14_identities(conn):
    n = conn.execute("SELECT COUNT(*) FROM identities").fetchone()[0]
    assert n == 14


def test_seed_covers_all_four_kinds(conn):
    kinds = {r[0] for r in conn.execute("SELECT DISTINCT kind FROM identities")}
    assert kinds == {"service_account", "api_key", "oauth_app", "ai_agent"}


def test_seed_is_deterministic():
    a = connect()
    b = connect()
    na = a.execute("SELECT COUNT(*) FROM usage_events").fetchone()[0]
    nb = b.execute("SELECT COUNT(*) FROM usage_events").fetchone()[0]
    assert na == nb > 0


# ---------- sprawl / lifecycle scoring ----------

def test_overprivileged_flagged_sprawl01(conn):
    s = sprawl.score_identity(conn, "svc-billing-01")
    assert s["least_privilege_ratio"] == pytest.approx(0.25)
    assert "SPRAWL-01" in s["flags"]


def test_stale_identity_flagged_sprawl02(conn):
    s = sprawl.score_identity(conn, "svc-etl-legacy")
    assert s["days_since_use"] == 121
    assert "SPRAWL-02" in s["flags"]


def test_never_rotated_secret_flagged_sprawl03(conn):
    s = sprawl.score_identity(conn, "svc-etl-legacy")
    assert s["days_since_rotation"] is None
    assert "SPRAWL-03" in s["flags"]


def test_orphan_flagged(conn):
    s = sprawl.score_identity(conn, "svc-etl-legacy")
    assert s["orphan"] is True
    assert "ORPHAN-01" in s["flags"]


def test_unvaulted_flagged(conn):
    s = sprawl.score_identity(conn, "svc-deploy-01")
    assert "VAULT-01" in s["flags"]


def test_healthy_identity_has_no_flags(conn):
    s = sprawl.score_identity(conn, "svc-monitoring")
    assert s["flags"] == []
    assert s["risk"] == 0


def test_worst_identity_ranks_first(conn):
    ranked = sprawl.remediation_list(conn)
    assert ranked[0]["id"] == "svc-etl-legacy"
    assert ranked[0]["risk"] == 1.0
    risks = [r["risk"] for r in ranked]
    assert risks == sorted(risks, reverse=True)


def test_recommended_action_orphan_stale(conn):
    s = sprawl.score_identity(conn, "svc-etl-legacy")
    assert sprawl.recommended_action(s).startswith("disable")


def test_recommended_action_rotation(conn):
    s = sprawl.score_identity(conn, "agent-code-reviewer")
    assert "SPRAWL-03" in s["flags"]
    assert sprawl.recommended_action(s) == "force secret rotation"


def test_recommended_action_trim_scopes(conn):
    s = sprawl.score_identity(conn, "oauth-crm-sync")
    assert sprawl.recommended_action(s) == "trim granted scopes to used scopes"


def test_unknown_identity_raises(conn):
    with pytest.raises(KeyError):
        sprawl.score_identity(conn, "nope")


# ---------- PAM: vault ----------

def test_vault_never_logs_plaintext():
    v = pam.Vault()
    a = AuditLog()
    ref = v.store("svc-deploy-01", "s3cr3t-hunter2")
    v.retrieve(ref, audit=a)
    blob = str(a.entries)
    assert "s3cr3t-hunter2" not in blob
    assert ref in blob


def test_vault_roundtrip():
    v = pam.Vault()
    ref = v.store("k1", "pw")
    assert v.retrieve(ref) == "pw"
    assert v.has(ref)


# ---------- PAM: JIT elevation ----------

def test_low_risk_elevation_auto_approved(conn):
    r = pam.request_elevation(conn, "svc-monitoring", "oncall-1")
    assert r["status"] == "approved"
    assert r["needs_confirmation"] is False


def test_high_risk_elevation_needs_confirmation(conn):
    r = pam.request_elevation(conn, "svc-etl-legacy", "oncall-1")
    assert r["risk"] > pam.CONFIRM_THRESHOLD
    assert r["needs_confirmation"] is True
    assert r["status"] == "pending"


def test_elevation_default_one_hour(conn):
    r = pam.request_elevation(conn, "svc-monitoring", "oncall-1")
    start = datetime.fromisoformat(
        conn.execute("SELECT requested_at FROM elevations WHERE id=?",
                     (r["id"],)).fetchone()[0])
    end = datetime.fromisoformat(r["expires_at"])
    assert (end - start).total_seconds() == pytest.approx(3600)


def test_confirm_high_risk_elevation(conn):
    r = pam.request_elevation(conn, "svc-etl-legacy", "oncall-1")
    out = pam.confirm_elevation(conn, r["id"], "sec-lead")
    assert out["status"] == "approved"
    assert out["confirmed_by"] == "sec-lead"


def test_unconfirmed_high_risk_stays_pending(conn):
    r = pam.request_elevation(conn, "svc-etl-legacy", "oncall-1")
    row = conn.execute("SELECT status FROM elevations WHERE id=?",
                       (r["id"],)).fetchone()
    assert row[0] == "pending"  # fail-closed: no action without confirmation


def test_confirm_expired_elevation_fails(conn):
    past = datetime(2026, 10, 18, 8, tzinfo=timezone.utc)
    r = pam.request_elevation(conn, "svc-etl-legacy", "oncall-1",
                              duration_h=0.001, now=past)
    with pytest.raises(ValueError, match="expired"):
        pam.confirm_elevation(conn, r["id"], "sec-lead",
                              now=datetime(2026, 10, 18, 12,
                                           tzinfo=timezone.utc))


def test_expire_elevations_marks_past(conn):
    past = datetime(2026, 10, 18, 8, tzinfo=timezone.utc)
    pam.request_elevation(conn, "svc-monitoring", "oncall-1",
                          duration_h=0.001, now=past)
    n = pam.expire_elevations(conn, now=datetime(2026, 10, 18, 12,
                                                tzinfo=timezone.utc))
    assert n >= 1


def test_active_elevation_lookup(conn):
    r = pam.request_elevation(conn, "svc-monitoring", "oncall-1")
    active = pam.active_elevation(conn, "svc-monitoring")
    assert active is not None and active["id"] == r["id"]


def test_session_record_has_no_secret(conn):
    r = pam.request_elevation(conn, "svc-monitoring", "oncall-1")
    sess = pam.session_record(conn, r["id"])
    assert "secret" not in str(sess).lower()
    assert sess["identity_id"] == "svc-monitoring"


def test_deny_elevation(conn):
    r = pam.request_elevation(conn, "svc-etl-legacy", "oncall-1")
    out = pam.deny_elevation(conn, r["id"], "sec-lead")
    assert out["status"] == "denied"


# ---------- ITDR ----------

def test_geo_signal_fires(conn):
    found = {f["identity_id"] for f in itdr.detect_first_seen_geo(conn)}
    assert "key-partner-feed" in found
    sig = [f for f in itdr.detect_first_seen_geo(conn)
           if f["identity_id"] == "key-partner-feed"][0]
    assert sig["signal_id"] == "SIG-GEO-01"


def test_impossible_travel_fires(conn):
    found = itdr.detect_impossible_travel(conn)
    assert any(f["identity_id"] == "key-iot-ingest" and
               f["signal_id"] == "SIG-TRAVEL-01" for f in found)


def test_usage_spike_fires(conn):
    found = itdr.detect_usage_spike(conn)
    assert any(f["identity_id"] == "key-mobile-app" and
               f["signal_id"] == "SIG-SPIKE-01" for f in found)


def test_token_reuse_fires(conn):
    found = itdr.detect_token_reuse(conn)
    assert any(f["signal_id"] == "SIG-REUSE-01" and
               "agent-data-labeler" in f["identity_id"] and
               "key-webhook" in f["identity_id"] for f in found)


def test_run_all_covers_four_signals(conn):
    sigs = {f["signal_id"] for f in itdr.run_all(conn)}
    assert sigs == {"SIG-GEO-01", "SIG-TRAVEL-01", "SIG-SPIKE-01",
                    "SIG-REUSE-01"}


# ---------- response ----------

def test_revoke_needs_confirmation(conn):
    with pytest.raises(respond.ConfirmationRequired):
        respond.revoke_key(conn, "key-partner-feed", confirmed=False,
                           dry_run=False)


def test_disable_needs_confirmation(conn):
    with pytest.raises(respond.ConfirmationRequired):
        respond.disable_identity(conn, "svc-etl-legacy", confirmed=False,
                                 dry_run=False)


def test_dry_run_changes_nothing(conn):
    before = conn.execute(
        "SELECT status FROM identities WHERE id='key-partner-feed'").fetchone()[0]
    respond.revoke_key(conn, "key-partner-feed", confirmed=True, dry_run=True)
    after = conn.execute(
        "SELECT status FROM identities WHERE id='key-partner-feed'").fetchone()[0]
    assert before == after == "active"


def test_confirmed_revoke_applies(conn):
    respond.revoke_key(conn, "key-partner-feed", confirmed=True, dry_run=False)
    status = conn.execute(
        "SELECT status FROM identities WHERE id='key-partner-feed'").fetchone()[0]
    assert status == "revoked"


def test_rotation_needs_no_confirmation(conn):
    r = respond.force_rotation(conn, "agent-code-reviewer", dry_run=False)
    assert r["effect"] == "secret_rotated=2026-10-18"
    row = conn.execute(
        "SELECT secret_rotated FROM identities WHERE id='agent-code-reviewer'"
    ).fetchone()[0]
    assert row == "2026-10-18"


def test_response_is_audited(conn):
    a = AuditLog()
    respond.force_rotation(conn, "svc-monitoring", dry_run=True, audit=a)
    assert a.kinds("response.rotate")
    assert a.verify()


def test_playbook_maps_critical_to_revoke(conn):
    finding = {"signal_id": "SIG-TRAVEL-01",
               "identity_id": "key-iot-ingest"}
    with pytest.raises(respond.ConfirmationRequired):
        respond.respond_to_finding(conn, finding, confirmed=False,
                                   dry_run=False)


# ---------- gateway: text checks ----------

def test_gateway_allows_view_query(conn):
    rows = views.run_query(conn, "SELECT id FROM v_identity_posture LIMIT 5")
    assert len(rows) == 5


def test_gateway_rejects_insert(conn):
    with pytest.raises(GatewayDenied, match="SEC-SELECT-01"):
        views.run_query(conn, "INSERT INTO identities VALUES ('x')")


def test_gateway_rejects_raw_table(conn):
    with pytest.raises(GatewayDenied, match="SEC-SELECT-03"):
        views.run_query(conn, "SELECT * FROM identities")


def test_gateway_rejects_sqlite_master(conn):
    with pytest.raises(GatewayDenied, match="SEC-SELECT-03"):
        views.run_query(conn, "SELECT * FROM sqlite_master")


def test_gateway_rejects_multi_statement(conn):
    with pytest.raises(GatewayDenied, match="SEC-SELECT-01"):
        views.run_query(conn, "SELECT 1; SELECT 2")


def test_gateway_caps_rows(conn):
    rows = views.run_query(conn, "SELECT * FROM v_identity_posture")
    assert len(rows) <= views.MAX_ROWS


# ---------- gateway: authorizer with text check BYPASSED ----------

def test_authorizer_denies_raw_table_without_text_check(conn):
    with pytest.raises(GatewayDenied, match="authorizer denied"):
        run_query_authorizer_only(conn, "SELECT * FROM identities")


def test_authorizer_denies_comma_join_bypass(conn):
    with pytest.raises(GatewayDenied, match="authorizer denied"):
        run_query_authorizer_only(
            conn, "SELECT * FROM identities, v_identity_posture")


def test_authorizer_denies_quoted_table_bypass(conn):
    with pytest.raises(GatewayDenied, match="authorizer denied"):
        run_query_authorizer_only(conn, 'SELECT * FROM "identities"')


def test_authorizer_denies_parenthesised_table_bypass(conn):
    with pytest.raises(GatewayDenied, match="authorizer denied"):
        run_query_authorizer_only(conn, "SELECT * FROM (identities)")


def test_authorizer_denies_comment_whitespace_bypass(conn):
    with pytest.raises(GatewayDenied, match="authorizer denied"):
        run_query_authorizer_only(conn, "SELECT/**/*/**/FROM/**/identities")


def test_authorizer_denies_sqlite_master_without_text_check(conn):
    with pytest.raises(GatewayDenied, match="authorizer denied"):
        run_query_authorizer_only(conn, "SELECT * FROM sqlite_master")


def test_authorizer_denies_load_extension(conn):
    with pytest.raises(GatewayDenied, match="authorizer denied"):
        run_query_authorizer_only(conn, "SELECT load_extension('x')")


def test_authorizer_allows_legit_view_query_without_text_check(conn):
    rows = run_query_authorizer_only(
        conn, "SELECT id FROM v_identity_posture WHERE kind='api_key'")
    assert {r["id"] for r in rows} == {"key-mobile-app", "key-partner-feed",
                                       "key-iot-ingest", "key-webhook"}


def test_authorizer_allows_count_over_view(conn):
    rows = run_query_authorizer_only(
        conn, "SELECT COUNT(*) AS n FROM v_stale_identities")
    assert rows[0]["n"] == 2


# ---------- views content ----------

def test_stale_view_lists_expected(conn):
    ids = {r["id"] for r in views.run_query(conn, "SELECT id FROM v_stale_identities")}
    assert ids == {"svc-etl-legacy", "oauth-analytics"}


def test_posture_view_counts_scopes(conn):
    row = views.run_query(
        conn, "SELECT scopes_granted_n, scopes_used_n FROM v_identity_posture"
              " WHERE id='svc-billing-01'")[0]
    assert row["scopes_granted_n"] == 8
    assert row["scopes_used_n"] == 2


# ---------- audit ----------

def test_audit_chain_verifies():
    a = AuditLog()
    a.record("x", {"n": 1})
    a.record("y", {"n": 2})
    assert a.verify()


def test_audit_tamper_detected():
    a = AuditLog()
    a.record("x", {"n": 1})
    a.entries[0]["kind"] = "tampered"
    assert not a.verify()


# ---------- PII scrubbing ----------

@pytest.mark.parametrize("raw", [
    "call me at (555) 123-4567 tomorrow",
    "call +1 (555) 123-4567 tomorrow",
    "reach 555.123.4567 after 5",
    "ssn 123-45-6789 on file",
    "mail ops@example.com the report",
])
def test_pii_scrubbed(raw):
    out = feedback.scrub(raw)
    assert "555" not in out and "123-45-6789" not in out
    assert "ops@example.com" not in out


def test_dates_survive_scrubbing():
    out = feedback.scrub("rotation due 2026-10-18, call (555) 123-4567")
    assert "2026-10-18" in out
    assert "[PHONE]" in out


def test_feedback_store_keeps_only_scrubbed():
    store = feedback.FeedbackStore()
    item = store.add("analyst", "key 123-45-6789 leaked on 2026-10-18")
    assert "[SSN]" in item["text"]
    assert "2026-10-18" in item["text"]


# ---------- orchestrator ----------

def test_agent_run_dry_run(conn):
    agent = PostureAgent(conn)
    out = agent.run(dry_run=True)
    assert out["ranked"][0]["id"] == "svc-etl-legacy"
    assert len(out["findings"]) >= 4
    assert len(out["proposals"]) > 0
    # dry-run: the run reports dry_run and executed items are rotations
    assert out["dry_run"] is True
    assert agent.audit.verify()


def test_agent_escalates_high_risk(conn):
    agent = PostureAgent(conn)
    out = agent.run(dry_run=True)
    escalated_ids = {str(p["identity_id"]) for p in out["escalated"]}
    assert "svc-etl-legacy" in escalated_ids


def test_agent_auto_only_rotations(conn):
    agent = PostureAgent(conn)
    out = agent.run(dry_run=True)
    for e in out["executed"]:
        assert e["result"]["action"] == "rotate"


# ---------- demo helpers ----------

def test_demo_sample_run():
    out = demo_helpers.sample_run()
    assert out["ranked"] and out["findings"]


def test_demo_audit_verify():
    assert demo_helpers.audit_verify_demo()
