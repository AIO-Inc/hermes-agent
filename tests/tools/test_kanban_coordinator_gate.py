"""Coordinator-only board gate: only a coordination board's roster may
create/assign cards on it, and coordinators may attach reports cross-card.

Two substrate guarantees added after the first live pilot:

1. ROUTING DEVIATION — a coordinator fanned a hive-board order into desk cards
   ON the hive board (not the recon board), so worker seats picked up hive-board
   cards. The charter rule "only coordinators cross the hive board" was a
   convention, not a guarantee. ``_enforce_coordinator_roster`` now refuses a
   card create/assign on a coordination board whose assignee is not in that
   board's coordinator roster (configurable via provenance-gate.json).

2. ATTACH LIMITATION — a coordinator could not attach a REPORT to a DIFFERENT
   card on its own coordination board ("refusing to mutate another task").
   ``_attach_guard`` now lets a roster coordinator attach cross-card onto its
   coordination board while every other caller stays task-scoped.
"""
import json

import pytest


@pytest.fixture
def kanban_home(tmp_path, monkeypatch):
    """Isolated kanban root with a live ``hive`` coordination board."""
    from hermes_cli import kanban_db as kb
    from hermes_cli import kanban_db_boards as kbb

    kb._INITIALIZED_PATHS.clear()
    kbb.create_board("hive")
    return kb.kanban_home()


def _write_gate(kb, coordinators, extra_boards=None):
    """Write provenance-gate.json with the given hive roster."""
    cfg = {"coordination_boards": {"hive": {"coordinators": coordinators}}}
    if extra_boards:
        cfg["coordination_boards"].update(extra_boards)
    p = kb.provenance_gate_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cfg), encoding="utf-8")


# --- Card create/assign guard ---


def test_hive_create_refuses_non_roster_assignee(kanban_home):
    from hermes_cli import kanban_db as kb
    from hermes_cli import kanban_db_connect as kbc

    with kbc.connect(board="hive") as conn:
        with pytest.raises(kb.CoordinatorRosterRefused) as exc:
            kb.create_task(conn, title="desk card", assignee="atlas")
        assert exc.value.assignee == "atlas"
        assert exc.value.board == "hive"
        assert exc.value.roster == ["henry", "prowler"]
        # No row written — the refusal is raise-before-INSERT.
        assert kb.list_tasks(conn) == []


def test_hive_create_allows_roster_assignee(kanban_home):
    from hermes_cli import kanban_db as kb
    from hermes_cli import kanban_db_connect as kbc

    with kbc.connect(board="hive") as conn:
        tid = kb.create_task(conn, title="goal", assignee="prowler")
        assert kb.get_task(conn, tid).assignee == "prowler"


def test_non_coordination_board_is_unaffected(kanban_home):
    """The gate is scoped to coordination boards; the default board is untouched."""
    from hermes_cli import kanban_db as kb
    from hermes_cli import kanban_db_connect as kbc

    with kbc.connect() as conn:  # default board
        tid = kb.create_task(conn, title="worker desk", assignee="atlas")
        assert kb.get_task(conn, tid).assignee == "atlas"


def test_hive_assign_refuses_non_roster_reassign(kanban_home):
    from hermes_cli import kanban_db as kb
    from hermes_cli import kanban_db_connect as kbc

    with kbc.connect(board="hive") as conn:
        tid = kb.create_task(conn, title="goal", assignee="prowler")
        with pytest.raises(kb.CoordinatorRosterRefused):
            kb.assign_task(conn, tid, "atlas")
        # Roster reassign is fine.
        assert kb.assign_task(conn, tid, "henry") is True
        assert kb.get_task(conn, tid).assignee == "henry"


def test_roster_is_configurable_via_provenance_gate(kanban_home):
    from hermes_cli import kanban_db as kb
    from hermes_cli import kanban_db_connect as kbc

    _write_gate(kb, ["henry", "prowler", "atlas"])
    with kbc.connect(board="hive") as conn:
        # Now atlas is in the roster -> allowed.
        tid = kb.create_task(conn, title="desk", assignee="atlas")
        assert kb.get_task(conn, tid).assignee == "atlas"
        # Someone still off-roster -> refused.
        with pytest.raises(kb.CoordinatorRosterRefused):
            kb.create_task(conn, title="intruder", assignee="sentry")


def test_empty_roster_fails_closed(kanban_home):
    """A coordination board with an empty roster refuses every assignee (never
    silently opens the board)."""
    from hermes_cli import kanban_db as kb
    from hermes_cli import kanban_db_connect as kbc

    _write_gate(kb, [])
    with kbc.connect(board="hive") as conn:
        with pytest.raises(kb.CoordinatorRosterRefused):
            kb.create_task(conn, title="goal", assignee="prowler")


def test_coordinator_only_false_disables_gate(kanban_home):
    from hermes_cli import kanban_db as kb
    from hermes_cli import kanban_db_connect as kbc

    p = kb.provenance_gate_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps(
            {"coordination_boards": {"hive": {"coordinators": ["henry"], "coordinator_only": False}}}
        ),
        encoding="utf-8",
    )
    with kbc.connect(board="hive") as conn:
        tid = kb.create_task(conn, title="any assignee", assignee="atlas")
        assert kb.get_task(conn, tid).assignee == "atlas"


# --- Coordinator cross-card attach path ---


def _b64(text):
    import base64
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def test_coordinator_can_attach_report_cross_card_on_hive(kanban_home, monkeypatch):
    from hermes_cli import kanban_db as kb
    from hermes_cli import kanban_db_connect as kbc
    from tools import kanban_tools as kt

    monkeypatch.setenv("HERMES_PROFILE", "prowler")
    with kbc.connect(board="hive") as conn:
        goal = kb.create_task(conn, title="hive goal", assignee="henry")
        agg = kb.create_task(conn, title="aggregation", assignee="prowler")
    monkeypatch.setenv("HERMES_KANBAN_TASK", agg)

    out = json.loads(kt._handle_attach({
        "task_id": goal, "filename": "report.md", "content_base64": _b64("REPORT"),
        "board": "hive",
    }))
    assert out["ok"] is True, out

    with kbc.connect(board="hive") as conn:
        attachments = kb.list_attachments(conn, goal)
        assert len(attachments) == 1
        assert attachments[0].filename == "report.md"


def test_non_coordinator_cannot_attach_cross_card_on_hive(kanban_home, monkeypatch):
    from hermes_cli import kanban_db as kb
    from hermes_cli import kanban_db_connect as kbc
    from tools import kanban_tools as kt

    monkeypatch.setenv("HERMES_PROFILE", "atlas")
    with kbc.connect(board="hive") as conn:
        goal = kb.create_task(conn, title="hive goal", assignee="henry")
    with kbc.connect() as conn:  # the worker's own card lives on the default board
        own = kb.create_task(conn, title="worker card", assignee="atlas")
    monkeypatch.setenv("HERMES_KANBAN_TASK", own)

    out = json.loads(kt._handle_attach({
        "task_id": goal, "filename": "report.md", "content_base64": _b64("REPORT"),
        "board": "hive",
    }))
    assert out.get("ok") is not True
    assert "refusing to mutate" in out.get("error", "")

    with kbc.connect(board="hive") as conn:
        assert kb.list_attachments(conn, goal) == []


def test_worker_still_task_scoped_on_default_board(kanban_home, monkeypatch):
    """The cross-card allowance does NOT loosen the existing worker-scope guard
    on non-coordination boards."""
    from hermes_cli import kanban_db as kb
    from hermes_cli import kanban_db_connect as kbc
    from tools import kanban_tools as kt

    monkeypatch.setenv("HERMES_PROFILE", "test-worker")
    with kbc.connect() as conn:  # default board
        own = kb.create_task(conn, title="own", assignee="test-worker")
        other = kb.create_task(conn, title="other", assignee="peer")
    monkeypatch.setenv("HERMES_KANBAN_TASK", own)

    out = json.loads(kt._handle_attach({
        "task_id": other, "filename": "x.txt", "content_base64": _b64("x"),
    }))
    assert out.get("ok") is not True
    assert "refusing to mutate" in out.get("error", "")
