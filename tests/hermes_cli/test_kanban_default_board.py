"""S4 — per-profile default board resolution (``kanban.default_board``).

The machine-wide ``<root>/kanban/current`` pointer silently retargets every seat: one
profile's ``boards switch`` changes which board *every other* seat without an explicit
``--board`` lands on. ``kanban.default_board`` makes board separation per-profile and
substrate-enforced instead of social.

Resolution order (``kanban_db.get_current_board``): context override (``--board`` /
``scoped_current_board``) > ``HERMES_KANBAN_BOARD`` > profile ``kanban.default_board`` >
``<root>/kanban/current`` (last resort) > ``default``.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from hermes_cli import kanban_db as kb


@pytest.fixture()
def isolated_kanban_home(tmp_path, monkeypatch):
    """Fresh HERMES_HOME with a clean kanban home (boards + current pointer)."""
    test_home = tmp_path / ".hermes"
    test_home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(test_home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    # No ambient board pins may interfere with resolution.
    for var in ("HERMES_KANBAN_BOARD", "HERMES_KANBAN_DB", "HERMES_KANBAN_HOME",
                "HERMES_KANBAN_TASK", "HERMES_DELEGATED_CHILD_CONTEXT"):
        monkeypatch.delenv(var, raising=False)
    yield test_home


def _write_profile_default(home: Path, slug: str) -> None:
    """Write a profile config.yaml carrying ``kanban.default_board``."""
    (home / "config.yaml").write_text(
        f"kanban:\n  default_board: {slug}\n", encoding="utf-8"
    )


def test_profile_default_board_resolves_without_board_flag(isolated_kanban_home):
    """(b) A profile WITH ``kanban.default_board`` resolves to it when ``--board``
    is omitted — even while the machine-wide ``current`` pointer names a DIFFERENT
    board (the cross-org retarget bug)."""
    home = isolated_kanban_home
    kb.create_board("acme")
    kb.create_board("beta")
    # Another seat ran `hermes kanban boards switch acme` — the global pointer now
    # names acme machine-wide. This seat must NOT follow it.
    kb.set_current_board("acme")
    _write_profile_default(home, "beta")

    assert kb.get_current_board() == "beta", (
        "a profile with default_board=beta must resolve beta, not the shared "
        f"current pointer (acme); got {kb.get_current_board()!r}"
    )


def test_profile_without_default_board_keeps_legacy_behavior(isolated_kanban_home):
    """(c) A profile WITHOUT ``kanban.default_board`` keeps prior behavior: it falls
    through to the shared ``current`` pointer."""
    kb.create_board("acme")
    kb.set_current_board("acme")

    assert kb.get_current_board() == "acme", (
        "a profile without default_board must keep resolving via the shared "
        f"current pointer; got {kb.get_current_board()!r}"
    )


def test_explicit_board_trumps_profile_default(isolated_kanban_home):
    """(a) Explicit ``--board`` (scoped_current_board) still wins over the profile
    default, the env pin, and the current pointer."""
    home = isolated_kanban_home
    kb.create_board("acme")
    kb.create_board("beta")
    kb.create_board("gamma")
    kb.set_current_board("acme")
    _write_profile_default(home, "beta")

    with kb.scoped_current_board("gamma"):
        assert kb.get_current_board() == "gamma", (
            "explicit --board must outrank kanban.default_board"
        )
    # Outside the explicit scope, the profile default resumes.
    assert kb.get_current_board() == "beta"


def test_no_silent_cross_board_landing_on_create(isolated_kanban_home):
    """(d) A card created without ``--board`` lands on the profile's default board,
    never on the board another seat left `current`."""
    home = isolated_kanban_home
    kb.init_db()
    kb.create_board("acme")
    kb.create_board("beta")
    kb.set_current_board("acme")  # another org's seat switched the global pointer
    _write_profile_default(home, "beta")

    from hermes_cli import kanban_db_connect as kbc

    # The seat's board resolution (no --board) must land on beta.
    with kbc.connect() as conn:  # connect() resolves the seat's board
        task_id = kb.create_task(conn, title="beta-org task")

    # The write went to beta, not acme.
    with kbc.connect(board="beta") as conn:
        rows = conn.execute("SELECT title FROM tasks").fetchall()
    assert any(r[0] == "beta-org task" for r in rows), (
        "task must land on the profile default board (beta)"
    )

    with kbc.connect(board="acme") as conn:
        rows = conn.execute("SELECT title FROM tasks").fetchall()
    assert not any(r[0] == "beta-org task" for r in rows), (
        "task must NOT silently land on the other org's board (acme) via the "
        "shared current pointer"
    )


def test_profile_default_board_must_exist_else_falls_through(isolated_kanban_home):
    """A ``default_board`` naming a non-existent board falls through (never errors,
    never fabricates a board) to the shared pointer / default."""
    home = isolated_kanban_home
    kb.create_board("acme")
    kb.set_current_board("acme")
    _write_profile_default(home, "does-not-exist")

    assert kb.get_current_board() == "acme", (
        "an unconfigured/missing default board must fall through to the current "
        f"pointer; got {kb.get_current_board()!r}"
    )
