"""Strict, view-aware authorizer tests (grokbot-portfolio review, 2026-10-18).

The text check is switched off in the gateway tests, so every denial here
comes from the SQLite authorizer alone: a base-table READ is allowed only
when SQLite reports it on behalf of an allowed view (view-name argument);
a READ whose view-name argument is None is denied; sqlite_master and
load_extension are always denied.
"""

import sqlite3

import pytest

from midsec import authz, views
from midsec.inventory import connect
from midsec.views import GatewayDenied as GatewayError

BASE, COL, VIEW = "identities", "scopes_granted", "v_identity_posture"
VIEWS = sorted(views.ALLOWED_VIEWS)


@pytest.fixture()
def conn():
    c = connect()
    views.install_views(c)
    yield c
    c.close()


def _authz(conn, sql, allowed=VIEWS):
    with authz.views_only(conn, allowed) as denied:
        try:
            rows = conn.execute(sql).fetchall()
        except sqlite3.DatabaseError:
            return None, list(denied)
    return rows, list(denied)


DIRECT_READS = [
    f"SELECT * FROM {BASE}, {VIEW}",
    f'SELECT/**/*/**/FROM/**/"{BASE}"/**/,/**/{VIEW}',
    f"SELECT * FROM {VIEW} JOIN ({BASE}) ON 1=1",
    f"SELECT * FROM {VIEW} WHERE EXISTS (SELECT 1 FROM main.[{BASE}] WHERE {COL} IS NOT NULL)",
    f'SELECT {COL} FROM\t"{BASE}"\n',
]


@pytest.mark.parametrize("sql", DIRECT_READS)
def test_gateway_denies_base_read_with_text_check_off(conn, monkeypatch, sql):
    monkeypatch.setattr(views, "_text_check", lambda _sql: None)
    with pytest.raises(GatewayError) as exc:
        views.run_query(conn, sql)
    assert "authorizer denied" in str(exc.value)
    assert BASE in str(exc.value)


@pytest.mark.parametrize("sql", DIRECT_READS)
def test_authorizer_alone_denies_base_read(conn, sql):
    rows, denied = _authz(conn, sql)
    assert rows is None and BASE in [d.lower() for d in denied]


@pytest.mark.parametrize("view", VIEWS)
def test_every_view_readable_and_self_join_not_denied(conn, view):
    for sql in (f"SELECT * FROM {view} LIMIT 3", f"SELECT a.* FROM {view} a, {view} b LIMIT 1"):
        rows, denied = _authz(conn, sql)
        assert rows is not None and denied == [], (sql, denied)


def test_sqlite_master_denied_even_if_allowed(conn):
    rows, denied = _authz(conn, "SELECT name FROM sqlite_master", allowed=VIEWS + ["sqlite_master"])
    assert rows is None and "sqlite_master" in denied


def test_load_extension_and_writes_denied(conn):
    for sql in ("SELECT load_extension('x')", f"DELETE FROM {BASE}", "PRAGMA table_info(sqlite_master)"):
        rows, denied = _authz(conn, sql)
        assert rows is None and denied, sql


def test_count_star_residual_returns_count_only(conn):
    # Documented residual: a column-free read of a table behind a view returns a count.
    rows, denied = _authz(conn, f"SELECT count(*) FROM {BASE}")
    assert rows is not None and isinstance(rows[0][0], int) and denied == []
