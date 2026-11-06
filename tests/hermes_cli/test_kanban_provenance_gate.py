"""``complete_task`` C-13 decision-provenance gate.

A card whose title/body/completion touches a consequential keyword (money /
reputation / irreversible-time) must carry a provenance block (Score + Choice +
alternatives). Default mode is ADVISORY (post a comment, never block); enforced
mode blocks with ``MissingProvenanceError`` and is opt-in per org via
``~/.hermes/kanban/provenance-gate.json``. ``bypass_receipt`` must NOT waive
provenance; ``bypass_provenance`` is the separate explicit override.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hermes_cli import kanban_db as kb
from hermes_cli import kanban_db_connect as kbc


PROVENANCE = (
    "Score: 0.9 Choice: refund the client in full Alternatives: do nothing, "
    "partial refund, full refund"
)


@pytest.fixture
def conn(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    db_path = kb.kanban_db_path(board="default")
    kb._INITIALIZED_PATHS.discard(str(db_path.resolve()))
    kb.init_db()
    with kbc.connect() as c:
        yield c


def _write_config(conn, mode):
    # Resolve the exact path the loader reads, so mode/keywords are deterministic.
    path = kb._provenance_gate_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"mode": mode, "keywords": list(kb.DEFAULT_PROVENANCE_KEYWORDS)}))


def _ready_task(conn, title="demo") -> str:
    tid = kb.create_task(conn, title=title, assignee="coder")
    assert kb.claim_task(conn, tid, claimer=kb._claimer_id()) is not None
    return tid


def _events(conn, tid):
    return [r["kind"] for r in conn.execute(
        "SELECT kind FROM task_events WHERE task_id = ? ORDER BY id", (tid,)
    ).fetchall()]


# ── (a) keyword-tagged card WITH provenance block → passes ─────────────────

def test_keyword_with_provenance_block_passes(conn):
    _write_config(conn, "advisory")
    tid = _ready_task(conn, title="Issue refund to client")
    assert kb.complete_task(conn, tid, result=PROVENANCE) is True
    assert conn.execute("SELECT status FROM tasks WHERE id = ?", (tid,)).fetchone()["status"] == "done"
    assert "completed" in _events(conn, tid)


# ── (b) enforced + keyword + no block → blocked ────────────────────────────

def test_enforced_keyword_no_block_raises(conn):
    _write_config(conn, "enforced")
    tid = _ready_task(conn, title="Wire transfer to vendor")
    with pytest.raises(kb.MissingProvenanceError) as exc:
        kb.complete_task(conn, tid, result="deployed to https://example.com/release")
    assert exc.value.task_id == tid
    assert "wire transfer" in exc.value.hits
    row = conn.execute("SELECT status FROM tasks WHERE id = ?", (tid,)).fetchone()
    assert row["status"] == "running"
    kinds = _events(conn, tid)
    assert "completion_blocked_missing_provenance" in kinds
    assert "completed" not in kinds


# ── (c) advisory + keyword + no block → NOT blocked, advisory comment ─────

def test_advisory_keyword_no_block_posts_comment(conn):
    _write_config(conn, "advisory")
    tid = _ready_task(conn, title="Process payment to supplier")
    assert kb.complete_task(conn, tid, result="deployed to https://example.com/release") is True
    assert conn.execute("SELECT status FROM tasks WHERE id = ?", (tid,)).fetchone()["status"] == "done"
    kinds = _events(conn, tid)
    assert "completion_provenance_advisory" in kinds
    assert "completed" in kinds
    comments = kb.list_comments(conn, tid)
    assert any(c.author == "provenance-gate" and "provenance" in c.body.lower() for c in comments)


def test_shadow_keyword_no_block_posts_comment(conn):
    _write_config(conn, "shadow")
    tid = _ready_task(conn, title="Deploy prod tonight")
    assert kb.complete_task(conn, tid, result="deployed to https://example.com/release") is True
    assert conn.execute("SELECT status FROM tasks WHERE id = ?", (tid,)).fetchone()["status"] == "done"
    assert "completion_provenance_advisory" in _events(conn, tid)


# ── (d) non-keyword card → unaffected ─────────────────────────────────────

def test_non_keyword_card_unaffected(conn):
    _write_config(conn, "enforced")
    tid = _ready_task(conn, title="Refactor the auth module")
    assert kb.complete_task(conn, tid, result="deployed to https://example.com/release") is True
    assert conn.execute("SELECT status FROM tasks WHERE id = ?", (tid,)).fetchone()["status"] == "done"
    kinds = _events(conn, tid)
    assert "completion_provenance_advisory" not in kinds
    assert "completion_blocked_missing_provenance" not in kinds


# ── (e) existing receipt-marker gate still works ──────────────────────────

def test_receipt_gate_still_blocks_nonempty_no_marker(conn):
    _write_config(conn, "advisory")
    tid = _ready_task(conn, title="Refactor the auth module")
    with pytest.raises(kb.MissingReceiptError):
        kb.complete_task(conn, tid, result="fixed the login bug")
    assert conn.execute("SELECT status FROM tasks WHERE id = ?", (tid,)).fetchone()["status"] == "running"
    assert "completion_blocked_missing_receipt" in _events(conn, tid)


# ── (f) bypass_receipt does NOT waive provenance ──────────────────────────

def test_bypass_receipt_does_not_waive_provenance(conn):
    _write_config(conn, "enforced")
    tid = _ready_task(conn, title="Sign contract with district")
    with pytest.raises(kb.MissingProvenanceError):
        kb.complete_task(conn, tid, result="signed", bypass_receipt=True)
    assert conn.execute("SELECT status FROM tasks WHERE id = ?", (tid,)).fetchone()["status"] == "running"


# ── (g) bypass_provenance is the explicit override ────────────────────────

def test_bypass_provenance_allows_close(conn):
    _write_config(conn, "enforced")
    tid = _ready_task(conn, title="Rotate keys for prod")
    assert kb.complete_task(conn, tid, result="rotated", bypass_receipt=True,
                            bypass_provenance=True) is True
    assert conn.execute("SELECT status FROM tasks WHERE id = ?", (tid,)).fetchone()["status"] == "done"


# ── (h) off mode disables the gate ─────────────────────────────────────────

def test_off_mode_disables_gate(conn):
    _write_config(conn, "off")
    tid = _ready_task(conn, title="Drop database for staging")
    assert kb.complete_task(conn, tid, result="deployed to https://example.com/release") is True
    assert conn.execute("SELECT status FROM tasks WHERE id = ?", (tid,)).fetchone()["status"] == "done"
    kinds = _events(conn, tid)
    assert "completion_provenance_advisory" not in kinds
    assert "completion_blocked_missing_provenance" not in kinds


# ── (i) no config file → advisory fallback (never blocks out of the box) ──

def test_no_config_file_falls_back_to_advisory(conn):
    # No provenance-gate.json written: the loader must fall back to advisory
    # + default keywords, so a fresh org never sees a surprise block.
    assert not kb._provenance_gate_config_path().exists()
    tid = _ready_task(conn, title="Process payment to supplier")
    assert kb.complete_task(conn, tid, result="deployed to https://example.com/release") is True
    assert conn.execute("SELECT status FROM tasks WHERE id = ?", (tid,)).fetchone()["status"] == "done"
    kinds = _events(conn, tid)
    assert "completion_blocked_missing_provenance" not in kinds
    assert "completed" in kinds

