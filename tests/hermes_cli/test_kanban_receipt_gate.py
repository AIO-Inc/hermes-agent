"""``complete_task`` receipt gate: a non-empty completion without a verifiable
evidence marker is refused (``MissingReceiptError``), with an explicit
``bypass_receipt`` override and a review-approval exemption.

This is the hard-block generalization of the receipt-on-close sweep: a 'done'
card must carry evidence a third party could verify the work against (URL, tx
hash, commit SHA, test/CI output, diff, packet_hash, 'verified by'), not just
non-empty prose.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hermes_cli import kanban_db as kb
from hermes_cli import kanban_db_connect as kbc


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


def _ready_task(conn) -> str:
    tid = kb.create_task(conn, title="demo", assignee="coder")
    assert kb.claim_task(conn, tid, claimer=kb._claimer_id()) is not None
    return tid


# ── (a) normal complete WITH a receipt still works ─────────────────────────

@pytest.mark.parametrize("marker", [
    "deployed to https://example.com/release-42",
    "settled on-chain: tx 0x1234567890abcdef1234567890abcdef",
    "landed commit abc1234",
    "pytest: 12 passed",
    "diff --git a/x.py b/x.py",
    "packet_hash verified",
    "verified by coordinator",
])
def test_complete_with_receipt_marker_succeeds(conn, marker):
    tid = _ready_task(conn)
    assert kb.complete_task(conn, tid, result=marker) is True
    assert conn.execute("SELECT status FROM tasks WHERE id = ?", (tid,)).fetchone()["status"] == "done"


# ── (b) receipt-less non-empty close is BLOCKED ─────────────────────────────

def test_nonempty_without_receipt_raises(conn):
    tid = _ready_task(conn)
    with pytest.raises(kb.MissingReceiptError):
        kb.complete_task(conn, tid, result="fixed the login bug")
    # No state change, auditable event landed.
    row = conn.execute("SELECT status, result FROM tasks WHERE id = ?", (tid,)).fetchone()
    assert row["status"] == "running"
    assert not row["result"]
    kinds = [r["kind"] for r in conn.execute(
        "SELECT kind FROM task_events WHERE task_id = ? ORDER BY id", (tid,)
    ).fetchall()]
    assert "completion_blocked_missing_receipt" in kinds
    assert "completed" not in kinds


def test_one_word_result_without_receipt_raises(conn):
    tid = _ready_task(conn)
    with pytest.raises(kb.MissingReceiptError):
        kb.complete_task(conn, tid, result="done")
    assert conn.execute("SELECT status FROM tasks WHERE id = ?", (tid,)).fetchone()["status"] == "running"


def test_stored_result_without_marker_also_raises(conn):
    tid = _ready_task(conn)
    conn.execute("UPDATE tasks SET result = ? WHERE id = ?", ("all finished", tid))
    conn.commit()
    with pytest.raises(kb.MissingReceiptError):
        kb.complete_task(conn, tid)


# ── (c) empty close still blocked ───────────────────────────────────────────

def test_empty_close_still_raises_empty_error(conn):
    tid = _ready_task(conn)
    with pytest.raises(kb.EmptyCompletionError):
        kb.complete_task(conn, tid)


# ── (d) bypass flag + review-approval exemption ─────────────────────────────

def test_bypass_receipt_allows_markerless_close(conn):
    tid = _ready_task(conn)
    with pytest.raises(kb.MissingReceiptError):
        kb.complete_task(conn, tid, result="superseded by a later card")
    # Explicit operator override closes it.
    assert kb.complete_task(conn, tid, result="superseded by a later card",
                            bypass_receipt=True) is True
    assert conn.execute("SELECT status FROM tasks WHERE id = ?", (tid,)).fetchone()["status"] == "done"


def test_review_approval_exempt_from_receipt_gate(conn):
    tid = kb.create_task(conn, title="review-me", assignee="coder")
    assert kb.claim_task(conn, tid, claimer=kb._claimer_id()) is not None
    assert kb.request_review(conn, tid, summary="please look") is True
    assert kb.get_task(conn, tid).status == "review"
    # No result text at all: review approval is the human's voucher, so both the
    # empty gate and the receipt gate stay exempt.
    assert kb.complete_task(conn, tid) is True
    assert kb.get_task(conn, tid).status == "done"
