"""Transcript-write secret redaction (sean-ops/t_1602bd9f, Option A).

Redacts ``sbp_`` and ``eyJ`` (JWT / service-role) secrets from message fields BEFORE a
message row is written to ``messages`` — and therefore before the FTS5 external-content
triggers (``messages_fts`` / ``messages_fts_trigram`` / ``messages_fts_cjk``) index it.
This is the single chokepoint that stops new leaks at source; it does not clean existing
residue (Option B / C handle that).

Design constraints (from the mitigation doc):

- **Prefix preserved for audit.** A redacted token keeps its ``sbp_`` / ``eyJ`` prefix plus
  a few characters, so an auditor can tell the token family without recovering the secret.
- **Anchored to real token shape.** ``sbp_`` requires 16+ characters of the token alphabet,
  so a legitimate short ``sbp_``-prefixed string (e.g. ``sbp_something_short``) is never
  redacted. ``eyJ`` requires the base64url header shape; a full compact JWT (three
  dot-separated base64url segments) is redacted whole, a bare/truncated ``eyJ`` token gets
  its header redacted.
- **Fail-open.** Any regex/encoding error returns the value un-redacted; the write is never
  dropped or corrupted by the hook.
- **Zero false positives on ordinary text.** Both prefixes (``sbp_``, ``eyJ``) plus the
  length/char-class anchor make a spurious match on prose effectively impossible.
"""

from __future__ import annotations

import os
import re
from typing import Any

REDACT_MARKER = "[REDACTED sean-ops/t_1602bd9f]"

# Characters kept after the ``sbp_`` / ``eyJ`` prefix, for audit correlation.
_AUDIT_KEEP_CHARS = 8

# ``sbp_`` tokens: the prefix plus 16+ characters of the token alphabet. The length floor is
# the false-positive guard — a short ``sbp_``-prefixed identifier never matches.
_SBP_RE = re.compile(r"sbp_[A-Za-z0-9_-]{16,}")

# A full compact JWT: ``eyJ…`` header, ``.``, payload, ``.``, signature — all base64url
# segments (the standard Supabase / service-role shape). Matched before the bare pattern so
# the whole token (not just the header) is redacted.
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{7,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}")

# A bare/truncated ``eyJ`` token (JWT header prefix, or an ``eyJ`` value whose payload is not
# clean base64url and so escapes the full-JWT pattern). Redacts the header at least.
_BARE_EYJ_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}")

# Config toggle. Default ON. Disable with ``sessions.transcript_secret_redaction: false`` in
# config.yaml, or the env var ``HERMES_TRANSCRIPT_SECRET_REDACTION`` (0/off/false/no).
_ENV_KEY = "HERMES_TRANSCRIPT_SECRET_REDACTION"
_CONFIG_KEY = "transcript_secret_redaction"
_enabled_cache: bool | None = None


def _replacement(match: "re.Match[str]") -> str:
    """Keep the prefix + a few audit characters, then the marker."""
    token = match.group(0)
    return token[:_AUDIT_KEEP_CHARS] + REDACT_MARKER


def redact_secrets(value: Any) -> Any:
    """Redact ``sbp_`` / ``eyJ`` secrets from *value* in place.

    A no-op for anything that is not a ``str``. For strings, full JWTs are redacted first,
    then ``sbp_`` tokens, then any remaining bare ``eyJ`` tokens. Any error returns *value*
    un-redacted (fail-open): the write proceeds with the original bytes rather than being
    dropped.
    """
    if not isinstance(value, str):
        return value
    try:
        value = _JWT_RE.sub(_replacement, value)
        value = _SBP_RE.sub(_replacement, value)
        value = _BARE_EYJ_RE.sub(_replacement, value)
        return value
    except Exception:
        return value


def redact_secrets_recursive(value: Any) -> Any:
    """Recurse through ``str`` / ``list`` / ``dict`` / ``tuple`` and redact every string leaf.

    Used for structured (multimodal) message content that may carry a secret nested in a part.
    Fail-open like :func:`redact_secrets`.
    """
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, dict):
        return {k: redact_secrets_recursive(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(redact_secrets_recursive(item) for item in value)
    return value


def redact_for_persist(value: Any) -> Any:
    """Toggle-aware redaction for one secret-bearing field (a no-op when the hook is disabled)."""
    return redact_secrets(value) if transcript_redaction_enabled() else value


def transcript_redaction_enabled() -> bool:
    """Whether the transcript-write redaction hook is active (default ``True``).

    Resolution order: env var (fresh each call, for ops/tests), then the cached
    ``sessions.transcript_secret_redaction`` config value. A missing key means ON.
    """
    global _enabled_cache
    env = os.environ.get(_ENV_KEY)
    if env is not None:
        return env.strip().lower() not in ("0", "false", "no", "off", "")
    if _enabled_cache is not None:
        return _enabled_cache
    try:
        from hermes_cli.config import load_config_readonly
        value = (load_config_readonly().get("sessions") or {}).get(_CONFIG_KEY)
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


def reset_redaction_cache() -> None:
    """Drop the cached toggle (test seam; also lets a runtime config edit take effect)."""
    global _enabled_cache
    _enabled_cache = None
