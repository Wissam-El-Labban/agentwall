"""Tests for the audit logging module."""

import json
from pathlib import Path

import pytest

from agentfirewall.audit import AuditLogger
from agentfirewall.engine import RuleResult, Verdict
from agentfirewall.schema import LoggingConfig


@pytest.fixture
def base_dir(tmp_path):
    """Create a temporary .agentfirewall directory."""
    af_dir = tmp_path / ".agentfirewall"
    af_dir.mkdir()
    return af_dir


def _make_result(verdict: Verdict, rule: str = "test.rule", detail: str = "test detail") -> RuleResult:
    return RuleResult(verdict=verdict, rule=rule, detail=detail)


class TestAuditLogger:
    def test_log_creates_file_and_dirs(self, base_dir):
        config = LoggingConfig(enabled=True, file="logs/firewall.log", level="warn")
        logger = AuditLogger(config, base_dir)
        result = _make_result(Verdict.DENY)

        logger.log_decision("command", "rm -rf /", result)

        log_file = base_dir / "logs" / "firewall.log"
        assert log_file.exists()
        assert log_file.stat().st_size > 0

    def test_log_json_format(self, base_dir):
        config = LoggingConfig(enabled=True, file="logs/firewall.log", level="warn")
        logger = AuditLogger(config, base_dir)
        result = _make_result(Verdict.DENY, rule="commands.blocklist[0]", detail="Blocked rm")

        logger.log_decision("command", "rm -rf /", result)

        log_file = base_dir / "logs" / "firewall.log"
        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 1

        entry = json.loads(lines[0])
        assert entry["action_type"] == "command"
        assert entry["target"] == "rm -rf /"
        assert entry["verdict"] == "deny"
        assert entry["rule"] == "commands.blocklist[0]"
        assert entry["detail"] == "Blocked rm"
        assert "timestamp" in entry

    def test_log_multiple_entries(self, base_dir):
        config = LoggingConfig(enabled=True, file="logs/firewall.log", level="info")
        logger = AuditLogger(config, base_dir)

        logger.log_decision("command", "ls -la", _make_result(Verdict.ALLOW))
        logger.log_decision("file", ".git/config", _make_result(Verdict.DENY))
        logger.log_decision("network", "evil.com", _make_result(Verdict.WARN))

        log_file = base_dir / "logs" / "firewall.log"
        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 3

        verdicts = [json.loads(line)["verdict"] for line in lines]
        assert verdicts == ["allow", "deny", "warn"]

    def test_disabled_logging_writes_nothing(self, base_dir):
        config = LoggingConfig(enabled=False, file="logs/firewall.log", level="warn")
        logger = AuditLogger(config, base_dir)

        logger.log_decision("command", "rm -rf /", _make_result(Verdict.DENY))

        log_file = base_dir / "logs" / "firewall.log"
        assert not log_file.exists()

    def test_warn_level_skips_allow(self, base_dir):
        config = LoggingConfig(enabled=True, file="logs/firewall.log", level="warn")
        logger = AuditLogger(config, base_dir)

        logger.log_decision("command", "ls", _make_result(Verdict.ALLOW))
        logger.log_decision("command", "rm -rf /", _make_result(Verdict.DENY))

        log_file = base_dir / "logs" / "firewall.log"
        lines = log_file.read_text().strip().split("\n")
        # Only the DENY should be logged (ALLOW is INFO level, filtered by WARN)
        assert len(lines) == 1
        assert json.loads(lines[0])["verdict"] == "deny"

    def test_info_level_includes_allow(self, base_dir):
        config = LoggingConfig(enabled=True, file="logs/firewall.log", level="info")
        logger = AuditLogger(config, base_dir)

        logger.log_decision("command", "ls", _make_result(Verdict.ALLOW))
        logger.log_decision("command", "rm -rf /", _make_result(Verdict.DENY))

        log_file = base_dir / "logs" / "firewall.log"
        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 2

    def test_action_types(self, base_dir):
        config = LoggingConfig(enabled=True, file="logs/firewall.log", level="info")
        logger = AuditLogger(config, base_dir)

        for action_type in ("command", "file", "network"):
            logger.log_decision(action_type, "target", _make_result(Verdict.ALLOW))

        log_file = base_dir / "logs" / "firewall.log"
        lines = log_file.read_text().strip().split("\n")
        types = [json.loads(line)["action_type"] for line in lines]
        assert types == ["command", "file", "network"]

    def test_timestamp_is_utc_iso(self, base_dir):
        config = LoggingConfig(enabled=True, file="logs/firewall.log", level="warn")
        logger = AuditLogger(config, base_dir)

        logger.log_decision("command", "rm -rf /", _make_result(Verdict.DENY))

        log_file = base_dir / "logs" / "firewall.log"
        entry = json.loads(log_file.read_text().strip())
        ts = entry["timestamp"]
        # Should be ISO format with UTC timezone
        assert "T" in ts
        assert ts.endswith("+00:00")


class TestLogActivity:
    """Tests for the log_activity method (log_all_activity feature)."""

    def test_log_activity_when_enabled(self, base_dir):
        config = LoggingConfig(enabled=True, file="logs/firewall.log", level="info", log_all_activity=True)
        logger = AuditLogger(config, base_dir)

        logger.log_activity("create", "new_file.txt")

        log_file = base_dir / "logs" / "firewall.log"
        assert log_file.exists()
        entry = json.loads(log_file.read_text().strip())
        assert entry["action_type"] == "create"
        assert entry["target"] == "new_file.txt"
        assert entry["verdict"] == "allow"
        assert entry["rule"] == "activity_log"

    def test_log_activity_disabled_by_default(self, base_dir):
        config = LoggingConfig(enabled=True, file="logs/firewall.log", level="info")
        logger = AuditLogger(config, base_dir)

        logger.log_activity("create", "new_file.txt")

        log_file = base_dir / "logs" / "firewall.log"
        # File may exist from handler setup, but should have no content
        if log_file.exists():
            assert log_file.read_text().strip() == ""

    def test_log_activity_skipped_when_logging_disabled(self, base_dir):
        config = LoggingConfig(enabled=False, file="logs/firewall.log", level="info", log_all_activity=True)
        logger = AuditLogger(config, base_dir)

        logger.log_activity("create", "new_file.txt")

        log_file = base_dir / "logs" / "firewall.log"
        assert not log_file.exists()

    def test_log_activity_mixed_with_decisions(self, base_dir):
        config = LoggingConfig(enabled=True, file="logs/firewall.log", level="info", log_all_activity=True)
        logger = AuditLogger(config, base_dir)

        logger.log_decision("command", "rm -rf /", _make_result(Verdict.DENY))
        logger.log_activity("create", "readme.md")

        log_file = base_dir / "logs" / "firewall.log"
        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0])["verdict"] == "deny"
        assert json.loads(lines[1])["verdict"] == "allow"
        assert json.loads(lines[1])["rule"] == "activity_log"
