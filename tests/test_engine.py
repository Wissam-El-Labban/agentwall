"""Tests for the rule evaluation engine."""

from pathlib import Path

import pytest

from agentfirewall.engine import Engine, Verdict
from agentfirewall.schema import (
    CommandsConfig,
    DenyOperation,
    FilesystemConfig,
    FirewallConfig,
    FirewallMode,
    NetworkConfig,
    SandboxConfig,
)


def _make_config(**overrides) -> FirewallConfig:
    """Create a FirewallConfig with sensible test defaults, applying overrides."""
    defaults = dict(
        mode=FirewallMode.ENFORCE,
        sandbox=SandboxConfig(root="/home/test/project", allow_escape=False),
        filesystem=FilesystemConfig(
            protected_paths=[".git/**", ".env"],
            deny_operations=[DenyOperation.DELETE],
        ),
        commands=CommandsConfig(
            blocklist=[
                "rm -rf /",
                "rm -rf ~",
                "git push --force",
                "git push*--force",
                "git reset --hard",
                "dd if=*of=/dev/*",
                "mkfs.*",
            ],
        ),
        network=NetworkConfig(
            allowed_hosts=["github.com", "api.openai.com"],
            deny_egress_to=["169.254.169.254", "metadata.google.internal"],
        ),
    )
    defaults.update(overrides)
    return FirewallConfig(**defaults)


# ── Command evaluation ──────────────────────────────────────


class TestCommandEvaluation:
    def test_safe_command_allowed(self):
        engine = Engine(_make_config())
        result = engine.evaluate_command("ls -la")
        assert result.verdict == Verdict.ALLOW

    def test_rm_rf_root_blocked(self):
        engine = Engine(_make_config())
        result = engine.evaluate_command("rm -rf /")
        assert result.verdict == Verdict.DENY
        assert "blocklist" in result.rule

    def test_rm_rf_home_blocked(self):
        engine = Engine(_make_config())
        result = engine.evaluate_command("rm -rf ~")
        assert result.verdict == Verdict.DENY

    def test_git_force_push_blocked(self):
        engine = Engine(_make_config())
        result = engine.evaluate_command("git push --force")
        assert result.verdict == Verdict.DENY

    def test_git_force_push_with_remote_blocked(self):
        engine = Engine(_make_config())
        result = engine.evaluate_command("git push origin main --force")
        assert result.verdict == Verdict.DENY

    def test_git_reset_hard_blocked(self):
        engine = Engine(_make_config())
        result = engine.evaluate_command("git reset --hard HEAD~3")
        assert result.verdict == Verdict.DENY

    def test_dd_to_device_blocked(self):
        engine = Engine(_make_config())
        result = engine.evaluate_command("dd if=/dev/zero of=/dev/sda bs=1M")
        assert result.verdict == Verdict.DENY

    def test_mkfs_blocked(self):
        engine = Engine(_make_config())
        result = engine.evaluate_command("mkfs.ext4 /dev/sda1")
        assert result.verdict == Verdict.DENY

    def test_normal_git_push_allowed(self):
        engine = Engine(_make_config())
        result = engine.evaluate_command("git push origin main")
        assert result.verdict == Verdict.ALLOW

    def test_normal_rm_allowed(self):
        engine = Engine(_make_config())
        result = engine.evaluate_command("rm temp.txt")
        assert result.verdict == Verdict.ALLOW

    def test_mode_off_allows_everything(self):
        config = _make_config(mode=FirewallMode.OFF)
        engine = Engine(config)
        result = engine.evaluate_command("rm -rf /")
        assert result.verdict == Verdict.ALLOW

    def test_audit_mode_warns_instead_of_deny(self):
        config = _make_config(mode=FirewallMode.AUDIT)
        engine = Engine(config)
        result = engine.evaluate_command("rm -rf /")
        assert result.verdict == Verdict.WARN
        assert "[AUDIT]" in result.detail


class TestAllowlistMode:
    def test_allowlist_permits_matching(self):
        config = _make_config(
            commands=CommandsConfig(allowlist=["ls*", "cat*"], blocklist=[]),
        )
        engine = Engine(config)
        assert engine.evaluate_command("ls -la").verdict == Verdict.ALLOW
        assert engine.evaluate_command("cat README.md").verdict == Verdict.ALLOW

    def test_allowlist_blocks_non_matching(self):
        config = _make_config(
            commands=CommandsConfig(allowlist=["ls*", "cat*"], blocklist=[]),
        )
        engine = Engine(config)
        result = engine.evaluate_command("rm -rf /")
        assert result.verdict == Verdict.DENY
        assert "allowlist" in result.rule


# ── File operation evaluation ───────────────────────────────


class TestFileOperations:
    def test_delete_git_blocked(self):
        engine = Engine(_make_config())
        result = engine.evaluate_file_operation(DenyOperation.DELETE, ".git/HEAD")
        assert result.verdict == Verdict.DENY
        assert "protected" in result.detail.lower()

    def test_delete_env_blocked(self):
        engine = Engine(_make_config())
        result = engine.evaluate_file_operation(DenyOperation.DELETE, ".env")
        assert result.verdict == Verdict.DENY

    def test_delete_regular_file_allowed(self):
        engine = Engine(_make_config())
        result = engine.evaluate_file_operation(DenyOperation.DELETE, "output.txt")
        assert result.verdict == Verdict.ALLOW

    def test_sandbox_escape_blocked(self):
        config = _make_config(sandbox=SandboxConfig(root="/home/test/project", allow_escape=False))
        engine = Engine(config)
        result = engine.evaluate_file_operation(DenyOperation.DELETE, "/etc/passwd")
        assert result.verdict == Verdict.DENY
        assert "sandbox" in result.detail.lower()

    def test_sandbox_escape_allowed_when_enabled(self):
        config = _make_config(sandbox=SandboxConfig(root="/home/test/project", allow_escape=True))
        engine = Engine(config)
        result = engine.evaluate_file_operation(DenyOperation.DELETE, "/tmp/harmless.txt")
        assert result.verdict == Verdict.ALLOW

    def test_non_denied_operation_allowed(self):
        """chmod is not in deny_operations by default, so it should be allowed."""
        engine = Engine(_make_config())
        result = engine.evaluate_file_operation(DenyOperation.CHMOD, ".git/HEAD")
        assert result.verdict == Verdict.ALLOW


# ── Network evaluation ──────────────────────────────────────


class TestNetworkEvaluation:
    def test_allowed_host_passes(self):
        engine = Engine(_make_config())
        result = engine.evaluate_network("github.com")
        assert result.verdict == Verdict.ALLOW

    def test_denied_host_blocked(self):
        engine = Engine(_make_config())
        result = engine.evaluate_network("169.254.169.254")
        assert result.verdict == Verdict.DENY

    def test_metadata_endpoint_blocked(self):
        engine = Engine(_make_config())
        result = engine.evaluate_network("metadata.google.internal")
        assert result.verdict == Verdict.DENY

    def test_unknown_host_blocked_when_allowlist_set(self):
        engine = Engine(_make_config())
        result = engine.evaluate_network("evil.example.com")
        assert result.verdict == Verdict.DENY

    def test_any_host_allowed_when_no_allowlist(self):
        config = _make_config(
            network=NetworkConfig(allowed_hosts=[], deny_egress_to=["169.254.169.254"]),
        )
        engine = Engine(config)
        result = engine.evaluate_network("anything.example.com")
        assert result.verdict == Verdict.ALLOW
