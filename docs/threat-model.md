# Threat model (STRIDE-lite)

| Threat | Mitigation in this repo |
|---|---|
| Spoofing: forged elevation request | `requested_by` recorded; high-risk needs a different named confirmer (PAM-SOD-01, tested); departed owners refused (PAM-DEPARTED-01) |
| Tampering: audit log edited | Hash chain with per-entry digest recomputation; `verify()` |
| Repudiation: "I didn't approve that" | Every decision/confirmation/detection in the audit log |
| Information disclosure: secrets in logs | Vault references only; session records exclude secrets (tested) |
| Denial of service: gateway row dump | `fetchmany` cap, no `fetchall`, no LIMIT rewriting |
| Elevation of privilege: gateway bypass to raw tables | Strict view-aware authorizer; `tests/test_authorizer_strict.py` runs with the text check off |
| Elevation of privilege: standing "temporary" access | Elevation capped at 8h (PAM-TTL-01); only active identities (PAM-STATUS-01) |
| Incomplete containment: shared token | Every identity using a reused token is revoked (RESP-REUSE-01) |

Residual: a column-free `count(*)` on a table behind a view can return a
row count (no values).

Out of scope: real vault hardening, network transport security, live IdP
integration — all synthetic here.
