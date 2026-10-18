# Domain notes: machine-identity security

## The problem

A typical enterprise has 10–50x more non-human identities than humans:
service accounts for batch jobs, API keys for integrations, OAuth apps for
SaaS sync, and now AI agent identities that act with tool permissions. They
are created quickly (a key for a demo, a service account for a migration)
and almost never cleaned up. The result is a standing population of
over-privileged, stale, orphaned credentials with old secrets — the exact
material attackers harvest first.

Human-focused UEBA does not cover this population: a service account has no
"logon hours" baseline, and "impossible travel" means something different
for a key than for a person.

## Core concepts

- **Lifecycle posture**: staleness (unused 90+ days), orphaning (owner left),
  over-privilege (granted vs used scopes), secret age. Each is a cheap,
  deterministic check; together they rank what to fix first.
- **Least privilege for machines**: ratio of used to granted scopes. Under
  0.5 is over-scoped and trimmable without behavior change.
- **PAM for non-humans**: secrets in a vault (by reference), privileged
  access as time-boxed elevation (default 1h) instead of standing access,
  confirmation gates for high-risk grants.
- **ITDR signals**: first-seen geography, impossible travel, usage spikes
  vs the identity's own baseline, and token reuse across identities (one
  credential, two owners = one of them is wrong).
- **Fail-closed automation**: the agent proposes; low-risk rotations run
  alone; revokes and disables wait for a human. Dry-run is the default.

## Why an agent fits

Posture review is continuous, boring, and high-volume — exactly what agents
are for — while the blast radius of a wrong revoke is high, which is why
every destructive step carries a confirmation gate and a hash-chained audit
trail.
