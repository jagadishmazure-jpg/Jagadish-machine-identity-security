# Threat model (STRIDE-lite)

| Threat | Mitigation in this repo |
|---|---|
| Spoofing: forged elevation request | `requested_by` recorded; high-risk needs a separate confirmer |
| Tampering: audit log edited | Hash chain with per-entry digest recomputation; `verify()` |
| Repudiation: "I didn't approve that" | Every decision/confirmation/detection in the audit log |
| Information disclosure: secrets in logs | Vault references only; session records exclude secrets (tested) |
| Denial of service: gateway row dump | `fetchmany` cap, no `fetchall`, no LIMIT rewriting |
| Elevation of privilege: gateway bypass to raw tables | Strict view-aware authorizer; bypass-class regression tests |

Out of scope: real vault hardening, network transport security, live IdP
integration — all synthetic here.
