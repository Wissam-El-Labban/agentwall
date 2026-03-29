"""AI-powered command evaluation using Claude API as a fallback for static rules."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

# In-memory cache for AI decisions
_cache: dict[str, bool] = {}

SYSTEM_PROMPT = """\
You are a security evaluator for a system firewall. Your job is to determine if a shell command is destructive or dangerous.

A command is DANGEROUS if it:
- Deletes, overwrites, or corrupts files/directories broadly (rm -rf, shred, find -delete)
- Modifies critical system files (/etc/passwd, /etc/shadow, bootloader)
- Kills system processes or services
- Exfiltrates data (curl/wget posting sensitive files)
- Installs malware or runs untrusted remote code (curl | sh, wget | bash)
- Modifies git history destructively (force push, reset --hard)
- Formats disks or partitions (mkfs, dd to devices)
- Changes permissions broadly (chmod -R 777 /)
- Disables security features (ufw disable, setenforce 0)
- Fork bombs or resource exhaustion

A command is SAFE if it:
- Reads files (cat, less, head, grep)
- Lists files (ls, find without -delete)
- Navigates directories (cd, pwd)
- Installs packages normally (pip install, apt install)
- Normal git operations (commit, push without --force, pull)
- Edits specific files (nano, vim, echo > specific-file)
- Runs tests or builds (pytest, make, npm run)

Respond with ONLY a JSON object: {"dangerous": true/false, "reason": "brief explanation"}
"""


def _get_cache_path() -> Path | None:
    """Return path to persistent cache file, or None if no config dir."""
    from agentfirewall.schema import find_config
    config_path = find_config()
    if config_path is None:
        return None
    return config_path.parent / "ai_cache.json"


def _load_cache() -> None:
    """Load persistent cache from disk."""
    global _cache
    cache_path = _get_cache_path()
    if cache_path and cache_path.exists():
        try:
            _cache = json.loads(cache_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            _cache = {}


def _save_cache() -> None:
    """Save cache to disk."""
    cache_path = _get_cache_path()
    if cache_path:
        try:
            cache_path.write_text(json.dumps(_cache), encoding="utf-8")
        except OSError:
            pass


def _cache_key(command: str) -> str:
    """Normalize command to a cache key."""
    return hashlib.md5(command.strip().lower().encode()).hexdigest()


def evaluate_with_ai(command: str, api_key: str | None = None) -> tuple[bool, str] | None:
    """Evaluate a command using Claude API.

    Returns (is_dangerous, reason) or None if AI is unavailable.
    The api_key can be passed directly (from config) or read from ANTHROPIC_API_KEY env var.
    """
    # Check cache first
    if not _cache:
        _load_cache()

    key = _cache_key(command)
    if key in _cache:
        entry = _cache[key]
        return entry["dangerous"], entry["reason"]

    # Check for API key: passed arg > env var
    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None

    try:
        import anthropic
    except ImportError:
        return None

    try:
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=150,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": f"Is this command dangerous?\n\n{command}"}],
        )

        text = response.content[0].text.strip()
        # Strip markdown code blocks if present (e.g. ```json ... ```)
        if text.startswith("```"):
            text = text.split("\n", 1)[1]  # remove first line (```json)
            text = text.rsplit("```", 1)[0].strip()  # remove closing ```
        # Parse JSON response
        result = json.loads(text)
        dangerous = bool(result.get("dangerous", False))
        reason = result.get("reason", "AI evaluation")

        # Cache the result
        _cache[key] = {"dangerous": dangerous, "reason": reason}
        _save_cache()

        return dangerous, reason

    except Exception:
        return None
