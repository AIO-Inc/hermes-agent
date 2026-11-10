"""Pre-update secret sweep (sean-ops/t_1602bd9f, Option C).

The sweep redacts ``sbp_`` / ``eyJ`` secrets from the backup/snapshot COPY of a SQLite
database — never the live source — so a backup never freezes a secret that predates the
transcript hook (Option A). Exercises :func:`hermes_state_sweep.sweep_secrets_from_copy`
directly, then the real wiring at the two update chokepoints (emergency ``.bak`` preflight
and the quick-snapshot copy).
"""

import sqlite3
from pathlib import Path

import pytest

from hermes_cli import backup_sqlite
from hermes_state_redaction import REDACT_MARKER
from hermes_state_sweep import reset_sweep_cache, sweep_secrets_from_copy

SBP_SECRET = "sbp_" + "aB3xK9mQ2nV8pL4tR6wY0zC5dE7fGhJkL9pQrS2w"  # 44 chars total (40-char tail)
JWT_SECRET = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzZXJ2aWNlX3JvbGUifQ.s3cr3ts1gn4tur3h3r3"
SECRET_NEEDLES = ("s3cr3ts1gn4tur3h3r3", SBP_SECRET[4:])


@pytest.fixture(autouse=True)
def _reset_toggle():
    reset_sweep_cache()
    yield
    reset_sweep_cache()


def _secret_db(path: Path, *, with_secret: bool) -> Path:
    """A minimal state.db with a ``messages`` table; the row bypasses the transcript hook."""
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, session_id TEXT, role TEXT, "
                 "content TEXT, tool_calls TEXT, timestamp REAL)")
    if with_secret:
        conn.execute(
            "INSERT INTO messages (session_id, role, content, tool_calls, timestamp) "
            "VALUES ('s', 'assistant', ?, ?, 1.0)",
            (f"the key is {SBP_SECRET} and token {JWT_SECRET}", f'{{"t": "{JWT_SECRET}"}}'),
        )
    else:
        conn.execute(
            "INSERT INTO messages (session_id, role, content, timestamp) "
            "VALUES ('s', 'assistant', 'a normal quarterly report, no secrets', 1.0)",
        )
    conn.commit()
    conn.close()
    return path


def _copy(src: Path, dst: Path) -> Path:
    assert backup_sqlite._safe_copy_db(src, dst)
    return dst


def _grep_text(path: Path, needle: str) -> bool:
    """grep -a-faithful: does any TEXT-ish cell contain *needle*?"""
    conn = sqlite3.connect(path)
    try:
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        for table in tables:
            try:
                cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
            except sqlite3.Error:
                continue
            for col in cols:
                try:
                    hit = conn.execute(
                        f"SELECT 1 FROM {table} WHERE CAST({col} AS TEXT) LIKE ? LIMIT 1",
                        (f"%{needle}%",),
                    ).fetchone()
                except sqlite3.Error:
                    continue
                if hit:
                    return True
    finally:
        conn.close()
    return False


class TestSweepCore:
    def test_secret_redacted_in_copy_live_untouched(self, tmp_path):
        """(a) A copy of a secret-bearing DB lands REDACTED (marker present); the source is
        untouched."""
        src = _secret_db(tmp_path / "src.db", with_secret=True)
        dst = _copy(src, tmp_path / "dst.db")

        summary = sweep_secrets_from_copy(dst)

        assert summary["error"] is None
        assert summary["swept"] is True
        assert summary["rows_redacted"] >= 1
        # Copy: secret gone, marker + audit prefix present.
        for needle in SECRET_NEEDLES:
            assert not _grep_text(dst, needle), f"secret fragment leaked into the copy: {needle!r}"
        assert _grep_text(dst, REDACT_MARKER)
        assert _grep_text(dst, "sbp_") and _grep_text(dst, "eyJ")  # audit prefix preserved
        # Live source: still holds the secret (never touched).
        assert _grep_text(src, SECRET_NEEDLES[0])
        assert _grep_text(src, SECRET_NEEDLES[1])

    def test_clean_source_byte_identical(self, tmp_path):
        """(b) A clean source → the copy is byte-identical (no false positive, no write)."""
        src = _secret_db(tmp_path / "src.db", with_secret=False)
        dst = _copy(src, tmp_path / "dst.db")
        before = dst.read_bytes()

        summary = sweep_secrets_from_copy(dst)

        assert summary["rows_redacted"] == 0
        assert summary["swept"] is False
        assert summary["error"] is None
        assert dst.read_bytes() == before  # byte-identical

    def test_short_sbp_like_string_not_redacted(self, tmp_path):
        """A legit short ``sbp_``-prefixed string is NOT a false positive."""
        conn = sqlite3.connect(tmp_path / "src.db")
        conn.execute("CREATE TABLE messages (content TEXT)")
        conn.execute("INSERT INTO messages VALUES ('the sbp_something_short flag')")
        conn.commit()
        conn.close()
        dst = _copy(tmp_path / "src.db", tmp_path / "dst.db")
        before = dst.read_bytes()

        summary = sweep_secrets_from_copy(dst)

        assert summary["rows_redacted"] == 0
        assert dst.read_bytes() == before

    def test_sweep_error_is_fail_open(self, tmp_path, monkeypatch):
        """(c) A sweep error returns an error summary and never raises; the copy stays intact."""
        from hermes_state_sweep import redact_secrets

        src = _secret_db(tmp_path / "src.db", with_secret=True)
        dst = _copy(src, tmp_path / "dst.db")

        def boom(_value):
            raise RuntimeError("redaction exploded")

        monkeypatch.setattr("hermes_state_sweep.redact_secrets", boom)
        summary = sweep_secrets_from_copy(dst)  # must not raise
        assert summary["error"] is not None
        # Copy is left intact (un-redacted but not corrupted).
        assert _grep_text(dst, SECRET_NEEDLES[0])

    def test_toggle_disables_sweep(self, tmp_path, monkeypatch):
        src = _secret_db(tmp_path / "src.db", with_secret=True)
        dst = _copy(src, tmp_path / "dst.db")
        monkeypatch.setenv("HERMES_PRE_UPDATE_SECRET_SWEEP", "0")
        reset_sweep_cache()

        summary = sweep_secrets_from_copy(dst)

        assert summary["skipped"] == "disabled"
        assert summary["rows_redacted"] == 0
        assert _grep_text(dst, SECRET_NEEDLES[0])  # secret survives: sweep disabled

    def test_sweep_leaves_no_wal_sidecars(self, tmp_path):
        """A WAL-mode source copy (backup() inherits the WAL flag) must not leak ``-wal`` /
        ``-shm`` sidecars after the sweep — the published artifact is self-contained."""
        src = tmp_path / "src.db"
        conn = sqlite3.connect(src)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE messages (content TEXT)")
        conn.execute("INSERT INTO messages VALUES (?)", (f"key {SBP_SECRET}",))
        conn.commit()
        conn.close()

        dst = _copy(src, tmp_path / "dst.db")
        assert dst.exists()
        sweep_secrets_from_copy(dst)

        sidecars = [p.name for p in tmp_path.iterdir() if p.name.startswith("dst.db")]
        assert sidecars == ["dst.db"], f"sweep leaked WAL sidecars next to the copy: {sidecars}"
        assert not _grep_text(dst, SBP_SECRET[4:])


class TestPreflightWiring:
    def test_preflight_bak_is_swept(self, tmp_path):
        """The emergency ``.bak`` preflight sweeps the COPY before publishing; source untouched."""
        home = tmp_path / "home"
        home.mkdir()
        _secret_db(home / "state.db", with_secret=True)

        result = backup_sqlite.preflight_state_db(home)

        bak = Path(result["path"])
        assert bak.exists()
        for needle in SECRET_NEEDLES:
            assert not _grep_text(bak, needle), f"secret frozen in emergency backup: {needle!r}"
        assert _grep_text(bak, REDACT_MARKER)
        # Source untouched.
        assert _grep_text(home / "state.db", SECRET_NEEDLES[0])


class TestSnapshotWiring:
    def test_snapshot_copy_is_swept(self, tmp_path):
        """The quick-snapshot ``.db`` copy path sweeps the destination before publish."""
        from hermes_cli import backup

        src = _secret_db(tmp_path / "state.db", with_secret=True)
        dst = tmp_path / "snap.db"
        assert backup._safe_copy_db(src, dst)
        backup._sweep_copy_secrets(dst)  # the wiring call the snapshot path makes

        for needle in SECRET_NEEDLES:
            assert not _grep_text(dst, needle), f"secret frozen in snapshot copy: {needle!r}"
        assert _grep_text(dst, REDACT_MARKER)
        assert _grep_text(src, SECRET_NEEDLES[0])  # source untouched


class TestFtsCleanup:
    def test_sweep_cleans_external_content_fts_indexes(self, tmp_path):
        """The sweep's UPDATE fires the external-content FTS triggers, so the copy's FTS index
        (``messages_fts`` / ``messages_fts_trigram``) loses the secret too — a ``grep -a`` byte
        sweep of the whole copy finds nothing."""
        from hermes_state import SessionDB

        src = tmp_path / "state.db"
        d = SessionDB(db_path=src)
        d.create_session("sess-sweep", source="cli")
        # Residue: bypass the transcript hook with a raw insert.
        d._conn.execute(
            "INSERT INTO messages (session_id, role, content, timestamp) VALUES (?, 'assistant', ?, 1.0)",
            ("sess-sweep", f"the key is {SBP_SECRET}"),
        )
        d._conn.commit()
        d.close()

        dst = _copy(src, tmp_path / "dst.db")
        summary = sweep_secrets_from_copy(dst)
        assert summary["rows_redacted"] >= 1

        # grep -a-faithful sweep of the COPY across every table/column (incl. FTS shadow tables).
        assert not _grep_text(dst, SBP_SECRET[4:])
        assert _grep_text(dst, REDACT_MARKER)
