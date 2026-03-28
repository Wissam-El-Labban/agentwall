"""Structured audit logging for firewall decisions."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

from agentfirewall.engine import RuleResult

# Map config level strings to logging constants
_LEVEL_MAP = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warn": logging.WARNING,
    "warning": logging.WARNING,
    "error": logging.ERROR,
}

# Map verdict strings to logging levels for filtering
_VERDICT_LEVEL = {
    "allow": logging.INFO,
    "deny": logging.WARNING,
    "warn": logging.WARNING,
}


class _JsonFormatter(logging.Formatter):
    """Formats log records as single-line JSON."""

    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(record.msg, sort_keys=False)


class AuditLogger:
    """Logs firewall decisions to a structured JSON log file."""

    def __init__(self, config, base_dir: Path) -> None:
        from agentfirewall.schema import LoggingConfig

        if not isinstance(config, LoggingConfig):
            raise TypeError(f"Expected LoggingConfig, got {type(config).__name__}")

        self._enabled = config.enabled
        self._logger = logging.getLogger("agentfirewall.audit")
        self._logger.handlers.clear()
        self._logger.propagate = False

        if not self._enabled:
            self._logger.addHandler(logging.NullHandler())
            return

        log_path = base_dir / config.file
        log_path.parent.mkdir(parents=True, exist_ok=True)

        handler = RotatingFileHandler(
            log_path,
            maxBytes=5 * 1024 * 1024,  # 5 MB
            backupCount=3,
            encoding="utf-8",
        )
        handler.setFormatter(_JsonFormatter())

        level = _LEVEL_MAP.get(config.level.lower(), logging.WARNING)
        self._logger.setLevel(level)
        handler.setLevel(level)
        self._logger.addHandler(handler)

    def log_decision(
        self,
        action_type: str,
        target: str,
        result: RuleResult,
    ) -> None:
        """Log a firewall decision as a JSON entry.

        Args:
            action_type: "command", "file", or "network"
            target: The command string, file path, or host
            result: The RuleResult from the engine evaluation
        """
        if not self._enabled:
            return

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action_type": action_type,
            "target": target,
            "verdict": result.verdict.value,
            "rule": result.rule,
            "detail": result.detail,
        }

        level = _VERDICT_LEVEL.get(result.verdict.value, logging.WARNING)
        self._logger.log(level, entry)
