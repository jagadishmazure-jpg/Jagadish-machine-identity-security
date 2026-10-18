# Machine Identity Security

**Recruiter summary.** Enterprises are minting machine identities — service
accounts, API keys, OAuth apps, AI agent identities — with no lifecycle, no
least-privilege enforcement, and no revocation story. This repo is the
non-human counterpart to human-focused UEBA: it inventories every machine
identity, scores its lifecycle posture, guards privileged access with
just-in-time elevation, detects identity threats (impossible travel, token
reuse, usage spikes, first-seen geo), and responds with confirmation-gated
automation. A ReAct-style posture agent runs the whole loop. Stdlib only;
the real test count is printed below and checked in CI.

> Synthetic data only. Thrennow Systems is a fictional company. This is an
> independent project, not affiliated with any company or vendor.

## Real run (rendered from a fresh run in CI)

<!-- run: python scripts/show_differentiator.py -->
```text
worst identity: svc-etl-legacy risk=1.0 flags=['SPRAWL-01', 'SPRAWL-02', 'SPRAWL-03', 'ORPHAN-01', 'VAULT-01']
runtime signals: {'SIG-GEO-01': 2, 'SIG-REUSE-01': 1, 'SIG-SPIKE-01': 1, 'SIG-TRAVEL-01': 1}
proposals: 11 -> auto 1, escalated 10 (dry run)
elevation requested by departed owner ex-chen: refused (PAM-DEPARTED-01)
elevation svc-etl-legacy: risk=1.0 status=pending
  confirm by data-oncall: refused (PAM-SOD-01)
  confirm by sec-oncall: approved
72h elevation: refused (PAM-TTL-01)
token reuse on ['agent-data-labeler', 'key-webhook']: RESP-CONF-01 until a human confirms
  confirmed (dry run): revoke ['agent-data-labeler', 'key-webhook']
```
<!-- /run -->

## How it works

1. **Inventory** (`midsec/inventory.py`) — synthetic SQLite with 14 machine
   identities across 4 kinds, usage events, elevations, departed owners.
2. **Lifecycle scoring** (`midsec/sprawl.py`) — least-privilege ratio plus
   staleness, orphaning, secret age, vault status → 0–1 risk with cited
   rule IDs (SPRAWL-01/02/03, ORPHAN-01, VAULT-01) → ranked remediation list.
3. **PAM** (`midsec/pam.py`) — reference-based vault (plaintext never logged);
   just-in-time elevation, default 1h, capped at 8h (PAM-TTL-01), auto-expires;
   risk > 0.7 needs a human confirmer who is not the requester (PAM-SOD-01),
   otherwise the request stays pending (fail-closed). Revoked or disabled
   identities cannot be elevated (PAM-STATUS-01), departed owners cannot
   request (PAM-DEPARTED-01), and low-risk auto-approvals are attributed to
   the policy, not the requester.
4. **ITDR** (`midsec/itdr.py`) — four signals with cited IDs: first-seen geo,
   impossible travel, usage spike, token reuse across identities.
5. **Response** (`midsec/respond.py`) — revoke/disable need explicit
   confirmation (RESP-CONF-01); dry-run by default; rotation is
   non-destructive and automatic. A shared token revokes every identity using
   it (RESP-REUSE-01); unknown identities raise instead of reporting an
   effect (RESP-KNOWN-01).
6. **Gateway** (`midsec/views.py` + `midsec/authz.py`) — 3 read-only views
   behind a SELECT-only gateway with the strict view-aware SQLite authorizer.
   `tests/test_authorizer_strict.py` switches the text check off and proves
   the authorizer alone denies base-table reads (comma joins, quoted and
   parenthesised names, `EXISTS` subqueries), `sqlite_master`, writes,
   PRAGMA and `load_extension`. Residual: a column-free `count(*)` on a
   table behind a view can return a row count, never values; the text check
   blocks the plain form.
7. **Agent** (`midsec/orchestrator.py`) — scan → detect → plan → act; low-risk
   rotations auto-execute, everything else escalates; every step audited.

## How this differs from sibling repos

Checked against the code of each repo, not only its README:

| Repo | What its code does | Overlap with this repo |
|---|---|---|
| `Jagadish-agent-identity-security` | Posture **scanner** for a cloud identity platform: detection rules over an exported inventory (dormant accounts, unrotated secrets, unowned workload identities, over-privileged agents, shared credentials, standing admin roles), privilege-path and blast-radius analysis to crown jewels | **Partial, stated honestly:** this repo's lifecycle scorer (SPRAWL-01/02/03, ORPHAN-01) asks the same questions as those detection rules. That scorer is context, not the point |
| `Jagadish-agent-auth-security` | **Authentication** mechanisms: JWT vs sessions, DPoP, mTLS, OAuth flows, delegation, refresh-token reuse detection | None in code. Its "reuse" is refresh-token family reuse at login; SIG-REUSE-01 here is one token fingerprint seen on two identities in usage logs |
| `Jagadish-soc-analyst-copilot` | Interactive investigation assistant | Different mode: this repo runs a continuous posture loop |

What is new here, shown by the run above: **time-boxed elevation** behind a
separation-of-duties gate, **runtime threat signals** from usage events
(first-seen geo, impossible travel, usage spike, cross-identity token use),
and a **confirmation-gated response playbook**. The scanner assesses a
snapshot; this repo operates the identities.

## Guardrails, each proven by a test

| Claim | Test (in `tests/`) |
|---|---|
| Plaintext secrets never appear in audit entries or session records | `test_vault_never_logs_plaintext`, `test_session_record_has_no_secret`, `test_vault_secret_never_in_audit_or_session` |
| Revoke and disable need explicit confirmation; dry run is the default | `test_revoke_needs_confirmation`, `test_disable_needs_confirmation`, `test_dry_run_changes_nothing` |
| High-risk elevations fail closed without a confirmer | `test_unconfirmed_high_risk_stays_pending` |
| The requester cannot confirm their own elevation | `test_requester_cannot_confirm_own_elevation` |
| Elevations are time-boxed (≤ 8h) and auto-expire | `test_elevation_duration_is_bounded`, `test_expire_elevations_marks_past`, `test_confirm_expired_elevation_fails` |
| Revoked identities and departed owners cannot get elevation | `test_revoked_identity_cannot_be_elevated`, `test_departed_owner_cannot_request_elevation` |
| A shared token revokes every identity using it | `test_token_reuse_revokes_every_identity_sharing_the_token` |
| Four threat signals detected | `test_geo_signal_fires`, `test_impossible_travel_fires`, `test_usage_spike_fires`, `test_token_reuse_fires` |
| Gateway denies base tables, schema, writes and `load_extension` with the text check off | `tests/test_authorizer_strict.py` |
| Every agent step audited; the chain detects tampering | `test_agent_run_audits_every_step_and_chain_verifies`, `test_audit_tamper_detected` |
| PII scrubbed before feedback storage | `test_pii_scrubbed`, `test_feedback_store_keeps_only_scrubbed` |

## Limitations

- Synthetic data; detectors are tuned to the seeded scenarios, not evaluated
  against real attacker behavior — the tests are regression checks.
- Impossible-travel math uses a 4-city coordinate table.
- No live identity-provider integration (planned, not built).

## Built / Written-not-run / Planned

| Status | Item |
|---|---|
| Built | Inventory, lifecycle scorer, PAM (vault + JIT + separation of duties), 4 ITDR signals, response playbook, strict gateway, posture agent, audit, PII scrubbing, CI (tests, ruff, docs check, brand check, gitleaks, CodeQL) |
| Written-not-run | Streamlit demo (`demo/app.py`, needs `pip install streamlit`) |
| Planned | Live IdP read-only connector, real vault backend, eval harness on red-team scenarios |

## Run it

```bash
python3 -m pytest tests/ -q
python3 scripts/count_tests.py
```

<!-- run: python scripts/count_tests.py -->
```text
104 tests collected
```
<!-- /run -->

## Standardization review (2026-10-18)

Bugs found in review and fixed, each with a regression test in
`tests/test_midsec.py` (section "review fixes"):

| ID | Bug | Fix |
|---|---|---|
| PAM-SOD-01 | The requester could confirm their own high-risk elevation | Confirmer must be a different, named person |
| PAM-TTL-01 | "Time-boxed" elevation accepted any duration (10,000 hours, zero, negative) | Duration must be in (0, 8h] |
| PAM-STATUS-01 | Revoked and disabled identities could still be elevated | Only active identities |
| PAM-DEPARTED-01 | A departed owner could request privileged access | Refused |
| PAM-AUTO-01 | Auto-approved elevations recorded the requester as the confirmer | Recorded as `policy:auto-low-risk` |
| RESP-REUSE-01 | A token shared by two identities revoked only the first | Every identity using it is revoked |
| RESP-KNOWN-01 | Revoking an unknown identity reported `status=revoked` | Raises; no false effect |
| AUDIT-COPY-01 | The audit kept a live reference to the caller's dict, so a later edit by the caller broke an untampered chain | Stores a copy |
| VIEW-SCOPE-01 | An empty scope list was counted as 1 scope | Counted as 0 |

Also: the fictional company name belonged to a real software product and
was replaced with an invented one (now Thrennow Systems); the README
compared against a sibling repo that does not exist, and named a cloud
vendor's products in the boundary section. Both are corrected above.

Docs: [domain notes](knowledge/domain-notes.md) ·
[architecture](knowledge/architecture.md) ·
[implementation guide](docs/implementation-guide.md) ·
[interview points](docs/interview-points.md) ·
[threat model](docs/threat-model.md) ·
[ADR-0001](docs/adr/0001-sqlite-authorizer-backstop.md)
