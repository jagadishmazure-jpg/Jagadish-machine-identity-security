# Machine Identity Security

**Recruiter summary.** Enterprises are minting machine identities — service
accounts, API keys, OAuth apps, AI agent identities — with no lifecycle, no
least-privilege enforcement, and no revocation story. This repo is the
non-human counterpart to human-focused UEBA: it inventories every machine
identity, scores its lifecycle posture, guards privileged access with
just-in-time elevation, detects identity threats (impossible travel, token
reuse, usage spikes, first-seen geo), and responds with confirmation-gated
automation. A ReAct-style posture agent runs the whole loop. 69 tests, all
green, stdlib only.

> Synthetic data only. Thrennow Systems is a fictional company. This is an
> independent project, not affiliated with any vendor.

## Real run (from the repo itself)

```
14 identities ranked — worst: svc-etl-legacy (risk 1.0:
  over-scoped, stale 121d, secret never rotated, orphaned, unvaulted)
5 threat findings across 4 signal types
  (SIG-GEO-01, SIG-TRAVEL-01, SIG-SPIKE-01, SIG-REUSE-01)
11 remediation proposals → 1 auto-executed (secret rotation),
  10 escalated for human confirmation (fail-closed)
High-risk JIT elevation: risk 1.0 → needs_confirmation=True,
  status stays "pending" until a human confirms
```

## How it works

1. **Inventory** (`midsec/inventory.py`) — synthetic SQLite with 14 machine
   identities across 4 kinds, usage events, elevations, departed owners.
2. **Lifecycle scoring** (`midsec/sprawl.py`) — least-privilege ratio plus
   staleness, orphaning, secret age, vault status → 0–1 risk with cited
   rule IDs (SPRAWL-01/02/03, ORPHAN-01, VAULT-01) → ranked remediation list.
3. **PAM** (`midsec/pam.py`) — reference-based vault (plaintext never logged);
   just-in-time elevation, default 1h, auto-expires; risk > 0.7 needs human
   confirmation, otherwise the request stays pending (fail-closed).
4. **ITDR** (`midsec/itdr.py`) — four signals with cited IDs: first-seen geo,
   impossible travel, usage spike, token reuse across identities.
5. **Response** (`midsec/respond.py`) — revoke/disable need explicit
   confirmation (RESP-CONF-01); dry-run by default; rotation is
   non-destructive and automatic.
6. **Gateway** (`midsec/views.py` + `midsec/authz.py`) — 3 read-only views
   behind a SELECT-only gateway with the strict view-aware SQLite authorizer.
   Regression tests prove the authorizer alone denies raw-table reads with
   the text check bypassed.
7. **Agent** (`midsec/orchestrator.py`) — scan → detect → plan → act; low-risk
   rotations auto-execute, everything else escalates; every step audited.

## How this differs from sibling repos

- **vs `ueba-insider-threat`**: that repo scores *human* behavioral baselines
  (logon times, data volumes per person). This repo scores *non-human*
  identities (service accounts, keys, agents) on lifecycle posture —
  staleness, orphaning, scope sprawl, secret age. Different population,
  different signals, shared audit/PII patterns.
- **vs `soc-analyst-copilot`**: the copilot is an interactive investigation
  assistant (NL → query plan → findings). This repo is continuous posture
  management with an autonomous remediation loop.
- **vs `agent-identity-security`**: that repo is a posture *scanner* for the
  Microsoft identity stack (Entra ID, PIM, Azure RBAC, Foundry agents) — it
  maps who can control what and finds routes to crown jewels across people,
  workloads, and AI agents. This repo is identity *lifecycle and PAM
  operations* for non-human identities: discovery, sprawl scoring, vaulting,
  JIT elevation, and ITDR response. Assessment vs operations; Azure-native vs
  stack-agnostic.
- **vs `agent-auth-security`**: that repo implements *authentication
  mechanisms* (JWT vs sessions, DPoP, OAuth 2.1, delegation) — how identities
  prove who they are. This repo governs what non-human identities may
  *access* over their lifetime — privilege sprawl, staleness, orphaning, and
  secret hygiene. AuthN vs lifecycle/authZ.

## Guardrails

- Secrets live behind vault references; plaintext never appears in logs,
  sessions, or audit entries (tested).
- Destructive responses (revoke, disable) require explicit confirmation;
  dry-run is the default.
- High-risk elevations fail closed without a human confirmer.
- SELECT-only gateway: text allowlist + SQLite authorizer backstop + fetch
  caps; writes, schema reads, and `load_extension` denied.

## Limitations

- Synthetic data; detectors are tuned to the seeded scenarios, not evaluated
  against real attacker behavior — the 69 tests are regression checks.
- Impossible-travel math uses a 4-city coordinate table.
- No live identity-provider integration (planned, not built).

## Built / Written-not-run / Planned

| Status | Item |
|---|---|
| Built | Inventory, lifecycle scorer, PAM (vault + JIT), 4 ITDR signals, response playbook, strict gateway, posture agent, audit, PII scrubbing, 69 tests |
| Written-not-run | Streamlit demo (`demo/app.py`, needs `pip install streamlit`) |
| Planned | Live IdP read-only connector, real vault backend, eval harness on red-team scenarios |

## Run it

```bash
python3 -m pytest tests/ -q
python3 scripts/count_tests.py
```

Docs: [domain notes](knowledge/domain-notes.md) ·
[architecture](knowledge/architecture.md) ·
[implementation guide](docs/implementation-guide.md) ·
[interview points](docs/interview-points.md) ·
[threat model](docs/threat-model.md) ·
[ADR-0001](docs/adr/0001-sqlite-authorizer-backstop.md)
