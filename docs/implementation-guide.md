# Implementation guide

## Setup

```bash
python3 -m pytest tests/ -q     # stdlib only; see README for the live count
python3 scripts/count_tests.py  # prints the real total
```

No dependencies beyond Python 3.10+. The Streamlit demo needs
`pip install streamlit` (lazy import; everything else is stdlib).

## Adapting to a real environment

1. Replace `inventory.seed()` with a read-only pull from the identity
   provider (list service accounts, keys, OAuth grants). Keep the same
   column contract.
2. Swap `pam.Vault` for the real vault's SDK; keep the reference-based
   interface so plaintext still never reaches logs.
3. Feed real auth logs into `usage_events`; the four ITDR signals work on
   any `(identity_id, ts, city, country, token_fp)` rows.
4. Start with `dry_run=True` on all responses; graduate rotation first,
   then revokes with confirmation.

## Key decisions (see ADRs)

- Authorizer-first gateway: the SQLite authorizer is the real backstop, the
  text check is defense in depth (ADR-0001).
- Fail-closed everywhere: pending elevations, unconfirmed revokes, and
  sub-threshold confidence all resolve to "do nothing, escalate".
