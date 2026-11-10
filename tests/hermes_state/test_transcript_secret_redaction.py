"""Transcript-write secret redaction hook (sean-ops/t_1602bd9f, Option A).

The hook redacts ``sbp_`` / ``eyJ`` (JWT/service-role) secrets at the single message
persistence chokepoint — ``SessionMessagesMixin._message_row_params`` — so neither the
``messages`` row nor the FTS5 indexes (``messages_fts`` / ``messages_fts_trigram``) that
its triggers maintain ever see the secret.

These tests exercise the real write path (``append_message`` / ``append_messages_batch``)
and then re-hunt the whole database (every table, every column, as TEXT) plus both FTS
indexes for the secret, exactly as a ``grep -a`` byte sweep would.
"""

import os

import pytest

from hermes_state import SessionDB
from hermes_state_redaction import REDACT_MARKER, reset_redaction_cache

SBP_SECRET = "sbp_" + "aB3xK9mQ2nV8pL4tR6wY0zC5dE7fGhJkL9pQrS2w"  # 44 chars total (40-char tail)
JWT_SECRET = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InNlcnZpY2Vfcm9sZSJ9."
    "s3cr3ts1gn4tur3h3r3"
)
# A fragment that only exists inside the secrets (the grep -a needle).
SECRET_NEEDLES = ("s3cr3ts1gn4tur3h3r3", SBP_SECRET[4:], JWT_SECRET)


@pytest.fixture()
def db(tmp_path):
    d = SessionDB(db_path=tmp_path / "state.db")
    d.create_session("sess-redact", source="cli")
    yield d
    d.close()


@pytest.fixture(autouse=True)
def _reset_toggle():
    reset_redaction_cache()
    yield
    reset_redaction_cache()


def _secret_message():
    return {
        "role": "assistant",
        "content": f"here is the key: {SBP_SECRET} and the token: {JWT_SECRET}",
        "tool_calls": [{"name": "terminal", "arguments": f'{{"token": "{JWT_SECRET}"}}'}],
        "reasoning": f"the secret sbp token is {SBP_SECRET}",
        "reasoning_content": f"service role {JWT_SECRET}",
        "api_content": f"exact api bytes {SBP_SECRET}",
    }


def _grep_db(db, needle: str) -> bool:
    """Re-hunt the whole database for *needle* across every table and column, as TEXT.

    The ``grep -a``-faithful sweep: SQLite ``state.db`` is binary, so a text-only sweep
    misses it; this walks every table/column including the FTS5 shadow tables
    (``*_fts_content`` / ``*_fts_data`` / ``*_fts_idx``).
    """
    conn = db._conn
    tables = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    for table in tables:
        try:
            cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
        except Exception:
            continue
        for col in cols:
            try:
                hit = conn.execute(
                    f"SELECT 1 FROM {table} WHERE CAST({col} AS TEXT) LIKE ? LIMIT 1",
                    (f"%{needle}%",),
                ).fetchone()
            except Exception:
                continue
            if hit:
                return True
    return False


def _fts_matches(db, needle: str) -> bool:
    """Does either FTS index find *needle* via a MATCH query?"""
    for idx in ("messages_fts", "messages_fts_trigram"):
        try:
            rows = db._conn.execute(
                f"SELECT rowid FROM {idx} WHERE {idx} MATCH ?", (f'"{needle}"*',)
            ).fetchall()
        except Exception:
            continue
        if rows:
            return True
    return False


class TestSecretRedaction:
    def test_sbp_and_jwt_redacted_in_messages_and_fts(self, db):
        """(a) A message with an sbp_ token and an eyJ JWT is redacted — prefix preserved,
        secret gone — in the persisted row AND both FTS indexes."""
        db.append_message("sess-redact", **_secret_message())

        # The row persisted (and counters bumped).
        assert db.message_count("sess-redact") == 1

        row = db._conn.execute(
            "SELECT content, tool_calls, reasoning, reasoning_content, api_content "
            "FROM messages WHERE session_id = ?", ("sess-redact",)
        ).fetchone()
        persisted = " ".join(str(c or "") for c in row)

        # Secret gone, prefix + marker present.
        assert SBP_SECRET not in persisted
        assert JWT_SECRET not in persisted
        assert "s3cr3ts1gn4tur3h3r3" not in persisted
        assert REDACT_MARKER in persisted
        assert "sbp_" in persisted and "eyJ" in persisted  # audit prefix preserved

        # Re-hunt the whole DB (messages + FTS shadow tables) for every secret needle.
        for needle in SECRET_NEEDLES:
            assert not _grep_db(db, needle), f"secret fragment leaked into state.db: {needle!r}"

        # And through the actual search indexes.
        assert not _fts_matches(db, "s3cr3ts1gn4tur3")

    def test_secret_in_batch_path_redacted(self, db):
        """The batch writer (CLI turn / gateway path) redacts identically."""
        msgs = [
            {"role": "assistant", "content": "show the key"},
            _secret_message(),
            {"role": "tool", "content": f"result {SBP_SECRET}", "tool_name": "t", "tool_call_id": "c1"},
        ]
        db.append_messages_batch("sess-redact", msgs)
        assert db.message_count("sess-redact") == 3
        assert not _grep_db(db, SBP_SECRET[4:])
        assert not _grep_db(db, "s3cr3ts1gn4tur3h3r3")

    def test_normal_message_byte_identical(self, db):
        """(b) A message with no secret is stored byte-identical (zero false positives).

        Uses an assistant row: a ``role='user'`` append pulls ``split_user_originated_turn``
        -> ``conversation_loop`` -> ``hermes_bootstrap``, whose module-level
        ``activate_dependencies`` reads the production install manifest when this checkout sits
        under ``~/.hermes`` (an environment quirk, not the hook). Redaction is role-agnostic, so
        the assistant row exercises the same ``_message_row_params`` chokepoint.
        """
        text = "The quarterly report is ready; let's review the numbers before the 3pm standup."
        db.append_message("sess-redact", "assistant", content=text)
        row = db._conn.execute(
            "SELECT content FROM messages WHERE session_id = ?", ("sess-redact",)
        ).fetchone()
        assert row[0] == text

    def test_short_sbp_like_string_not_redacted(self, db):
        """(c) A legit short ``sbp_``-prefixed string is NOT redacted."""
        text = "the sbp_something_short flag was set"  # tail 15 chars < 16
        db.append_message("sess-redact", "assistant", content=text)
        row = db._conn.execute(
            "SELECT content FROM messages WHERE session_id = ?", ("sess-redact",)
        ).fetchone()
        assert row[0] == text
        assert REDACT_MARKER not in row[0]

    def test_persistence_succeeds_and_marker_round_trips(self, db):
        """(d) Persistence still succeeds and the redacted row reads back cleanly."""
        db.append_message("sess-redact", **_secret_message())
        loaded = db.get_messages("sess-redact")
        assert loaded
        text = " ".join(str(m.get("content") or "") for m in loaded)
        assert SBP_SECRET not in text
        assert REDACT_MARKER in text

    def test_toggle_disables_redaction(self, db, monkeypatch):
        """Config toggle OFF leaves the secret un-redacted (hook is a no-op)."""
        monkeypatch.setenv("HERMES_TRANSCRIPT_SECRET_REDACTION", "0")
        reset_redaction_cache()
        db.append_message("sess-redact", **_secret_message())
        row = db._conn.execute(
            "SELECT content FROM messages WHERE session_id = ?", ("sess-redact",)
        ).fetchone()
        assert SBP_SECRET in row[0]  # un-redacted: the toggle disabled the hook
        assert REDACT_MARKER not in row[0]
