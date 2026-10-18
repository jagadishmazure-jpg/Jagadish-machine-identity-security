# Interview points

- **Why machine identity, not more UEBA?** UEBA baselines humans; service
  accounts and agent identities have no "working hours". Lifecycle posture
  (stale/orphan/over-scoped/old secret) is the right signal set.
- **Least-privilege ratio**: used/granted scopes under 0.5 is trimmable
  without behavior change — a cheap, defensible first cut.
- **JIT over standing access**: privileged machine access as 1-hour
  elevations (capped at 8h) that auto-expire; risk > 0.7 needs a human who
  is not the requester. Review found self-confirmation was possible; it is
  now refused and tested.
- **Fail-closed automation**: the agent auto-runs only rotations; revokes
  and disables wait for confirmation. Dry-run by default.
- **Gateway backstop**: a real bypass class (comma joins, quoted names,
  parenthesised tables) defeated text-only checks in a sibling project;
  here the SQLite authorizer denies raw-table reads even with the text
  check bypassed — proven by regression tests.
- **Vault discipline**: secrets by reference; plaintext never in logs,
  sessions, or audit (tested).
