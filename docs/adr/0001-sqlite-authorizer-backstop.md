# ADR-0001: SQLite authorizer as the gateway backstop

## Context

A text-only SELECT gateway can be bypassed: comma joins
(`FROM identities, v_identity_posture`), double-quoted identifiers
(`FROM "identities"`), parenthesised tables (`FROM (identities)`), and
`/**/` comments in place of whitespace all reach base tables without a
`FROM <name>` token for a regex to match. A sibling project confirmed this
bypass class returns real rows with the text check in place.

## Decision

Enforce access with SQLite's `set_authorizer` as the primary control:

- A base-table READ is allowed only when the authorizer's `source` argument
  names an allowed view (i.e., SQLite is reading the table on behalf of a
  view), or when the table itself is an allowed view.
- `sqlite_master`/`sqlite_schema`, PRAGMA, ATTACH, writes, and
  `load_extension` are always denied.
- The text-level check (SEC-SELECT-01/02/03) remains as defense in depth.

Narrow exception: SQLite reports an empty-column read with no view name for
tables behind a view that supply no columns (self-join sides, `count(*)`);
these are allowed only for tables behind allowed views, since no column
data is returned.

## Consequences

- Regression tests run the authorizer **with the text check bypassed** and
  prove raw-table reads are denied — this is a standing rule for all future
  gateway work.
- View self-joins keep working via the empty-column exception.
