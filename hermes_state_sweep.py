"""Pre-update secret sweep (sean-ops/t_1602bd9f, Option C).

Redacts ``sbp_`` / ``eyJ`` (JWT / service-role) secrets from a BACKUP/SNAPSHOT COPY of a
SQLite database, in place, so a backup never freezes a secret that predates the transcript
hook (Option A). The live ``state.db`` is never touched here — it is protected at source by
the transcript hook (Option A) and the janitor cron (Option B).

Design constraints (from the mitigation doc):

- **Copy-only.** This module operates on the just-written COPY (the ``.bak`` emergency
  snapshot, the ``state-snapshots/<id>/state.db`` quick-snapshot, the ``*.zip`` staged
  ``.db``), never on the source it was copied from.
- **Reuses the hook's regexes.** It imports :func:`hermes_state_redaction.redact_secrets`
  (single-string redaction) rather than duplicating the ``sbp_`` / ``eyJ`` patterns, so the
  two layers can never drift.
- **Fail-open.** Any error (bad SQLite, unimportable hook, trigger failure, lock) returns a
  summary dict and never raises: the caller's backup/update continues with the original
  copy. A secret that survives a failed sweep is the lesser evil than a corrupted or
  aborted backup.
- **Zero false positives / byte-identical clean path.** A read-only pre-scan (``LIKE`` on
  ``sbp_`` / ``eyJ``) decides whether any text column holds a candidate; if none, the write
  connection is never opened and the copy is left byte-identical.

Config toggle. Default ON. Disable with ``updates.pre_update_secret_sweep: false`` in
config.yaml, or the env var ``HERMES_PRE_UPDATE_SECRET_SWEEP`` (0/off/false/no).

FTS note: for the v23 external-content layout (the default), the ``messages_fts*`` triggers
fire on the sweep's ``UPDATE`` and re-tokenize the redacted value, so the copy's index loses
the secret too. The legacy opt-in inline-FTS layout is not auto-synced by those triggers and
is out of scope for this sweep (the transcript hook + janitor cover the live DB; a legacy
inline index in a backup is a pre-existing, deprecated shape).
"""

from __future__ import annotations

import contextlib
import logging
import os
import sqlite3
from pathlib import Path
from typing import Any

from hermes_state_redaction import redact_secrets

logger = logging.getLogger(__name__)

# Config toggle (default ON), parallel to the transcript hook's.
_ENV_KEY = "HERMES_PRE_UPDATE_SECRET_SWEEP"
_CONFIG_SECTION = "updates"
_CONFIG_KEY = "pre_update_secret_sweep"
_enabled_cache: bool | None = None


def _quote(ident: str) -> str:
    return '"' + ident.replace('"', '""') + '"'


def _remove_sidecars(path: Path) -> None:
    """Unlink WAL/journal sidecars the sweep's own connections may have created.

    ``_safe_copy_db`` (``sqlite3.backup()``) produces a fully-checkpointed copy whose header
    still carries the source's ``journal_mode=WAL`` flag, so any connection we open re-creates
    ``-wal`` / ``-shm`` next to it. The copy is a final, unpublished backup artifact (no other
    handle holds it), so those sidecars hold no uncheckpointed data and must not be published
    alongside the snapshot/backup — a ``.db`` paired with stale sidecars is exactly the
    torn-restore hazard the backup path already excludes. Best-effort.
    """
    for suffix in ("-wal", "-shm", "-journal"):
        with contextlib.suppress(OSError):
            Path(f"{path}{suffix}").unlink(missing_ok=True)


def sweep_enabled() -> bool:
    """Whether the pre-update backup secret sweep is active (default ``True``).

    Resolution order mirrors :func:`hermes_state_redaction.transcript_redaction_enabled`:
    env var (fresh each call, for ops/tests), then the cached
    ``updates.pre_update_secret_sweep`` config value. A missing key means ON.
    """
    global _enabled_cache
    env = os.environ.get(_ENV_KEY)
    if env is not None:
        return env.strip().lower() not in ("0", "false", "no", "off", "")
    if _enabled_cache is not None:
        return _enabled_cache
    try:
        from hermes_cli.config import load_config_readonly
        cfg = load_config_readonly() or {}
        section = cfg.get(_CONFIG_SECTION) if isinstance(cfg, dict) else {}
        value = (section or {}).get(_CONFIG_KEY) if isinstance(section, dict) else None
    except Exception:
        value = None
    if value is None:
        _enabled_cache = True
    elif isinstance(value, bool):
        _enabled_cache = value
    elif isinstance(value, str):
        _enabled_cache = value.strip().lower() not in ("0", "false", "no", "off", "")
    else:
        _enabled_cache = bool(value)
    return _enabled_cache


def reset_sweep_cache() -> None:
    """Drop the cached toggle (test seam; also lets a runtime config edit take effect)."""
    global _enabled_cache
    _enabled_cache = None


def _is_text_type(declared: str) -> bool:
    t = (declared or "").upper()
    return any(k in t for k in ("TEXT", "CHAR", "CLOB", "VARCHAR"))


def _has_candidate(conn: sqlite3.Connection, table: str, col: str) -> bool:
    q = (
        f"SELECT 1 FROM {_quote(table)} "
        f"WHERE {_quote(col)} LIKE '%sbp_%' OR {_quote(col)} LIKE '%eyJ%' LIMIT 1"
    )
    return conn.execute(q).fetchone() is not None


def sweep_secrets_from_copy(db_path: Any) -> dict:
    """Redact ``sbp_`` / ``eyJ`` secrets from the SQLite COPY at *db_path*, in place.

    Returns a summary dict::

        {"swept": bool, "rows_redacted": int, "tables": int, "columns": int,
         "skipped": str | None, "error": str | None}

    Never raises (fail-open). When disabled or when no candidate text is present, the file
    is left untouched (byte-identical).
    """
    summary: dict = {
        "swept": False,
        "rows_redacted": 0,
        "tables": 0,
        "columns": 0,
        "skipped": None,
        "error": None,
    }
    if not sweep_enabled():
        summary["skipped"] = "disabled"
        return summary
    path = Path(db_path)
    if not path.is_file():
        return summary

    conn: sqlite3.Connection | None = None
    try:
        # Fast path: a read-only scan decides whether any text column holds a candidate.
        # If not, we never open a write connection, so a clean copy stays byte-identical.
        ro = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
        try:
            tables = [
                r[0]
                for r in ro.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '%_fts%'"
                ).fetchall()
            ]
            targets: list[tuple[str, str]] = []
            for table in tables:
                try:
                    cols = [
                        r[1]
                        for r in ro.execute(f"PRAGMA table_info({_quote(table)})").fetchall()
                        if _is_text_type(r[2])
                    ]
                except sqlite3.Error:
                    continue
                for col in cols:
                    summary["columns"] += 1
                    try:
                        if _has_candidate(ro, table, col):
                            targets.append((table, col))
                    except sqlite3.Error:
                        continue
            if not targets:
                return summary
        finally:
            ro.close()

        # Slow path: redact in place on a write connection. Only candidate rows are read
        # and re-written; the UPDATE fires the external-content FTS triggers, so the copy's
        # index is re-tokenized from the redacted value.
        conn = sqlite3.connect(str(path))
        redacted_tables: set[str] = set()
        for table, col in targets:
            q = (
                f"SELECT rowid, {_quote(col)} FROM {_quote(table)} "
                f"WHERE {_quote(col)} LIKE '%sbp_%' OR {_quote(col)} LIKE '%eyJ%'"
            )
            for rowid, value in conn.execute(q):
                if not isinstance(value, str):
                    continue
                redacted = redact_secrets(value)
                if redacted != value:
                    conn.execute(
                        f"UPDATE {_quote(table)} SET {_quote(col)} = ? WHERE rowid = ?",
                        (redacted, rowid),
                    )
                    summary["rows_redacted"] += 1
                    redacted_tables.add(table)
        conn.commit()
        # Flush any WAL bytes into the main file (the copy inherits the source's WAL flag)
        # so the published artifact is self-contained once its sidecars are removed.
        with contextlib.suppress(sqlite3.Error):
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        summary["swept"] = True
        summary["tables"] = len(redacted_tables)
    except Exception as exc:
        summary["error"] = f"{type(exc).__name__}: {exc}"
        if conn is not None:
            try:
                conn.rollback()
            except Exception:
                pass
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        _remove_sidecars(path)
    return summary
