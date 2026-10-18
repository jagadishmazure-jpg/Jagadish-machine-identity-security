# Architecture

```mermaid
flowchart TD
    INV["inventory.py\nSQLite: identities, usage_events,\nelevations, departed_owners"] --> SPRAWL["sprawl.py\nlifecycle scorer\nSPRAWL-01/02/03, ORPHAN-01, VAULT-01"]
    INV --> ITDR["itdr.py\nSIG-GEO-01, SIG-TRAVEL-01,\nSIG-SPIKE-01, SIG-REUSE-01"]
    INV --> VIEWS["views.py\nv_identity_posture\nv_stale_identities\nv_elevation_history"]
    VIEWS --> AUTHZ["authz.py\nstrict view-aware authorizer"]
    SPRAWL --> ORCH["orchestrator.py\nscan → detect → plan → act"]
    ITDR --> ORCH
    ORCH --> PAM["pam.py\nvault + JIT elevation\nconfirmation gates"]
    ORCH --> RESP["respond.py\nrevoke / disable / rotate\nRESP-CONF-01, dry-run default"]
    PAM --> AUDIT["audit.py\nhash-chained log"]
    RESP --> AUDIT
    ORCH --> AUDIT
    FB["feedback.py\nPII scrubbing"] --> AUDIT
```

Data flow: the posture agent reads only through the gateway views, scores
and detects, then acts through PAM/response — every mutation audited, every
destructive step confirmation-gated.
