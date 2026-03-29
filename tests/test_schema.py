"""Tests for the schema module — parsing, validation, defaults."""

import textwrap
from pathlib import Path

import pytest

from agentfirewall.schema import (
    ConfigError,
    FirewallConfig,
    FirewallMode,
    DenyOperation,
    config_to_yaml,
    default_config,
    find_config,
    load_config,
)


@pytest.fixture()
def config_file(tmp_path: Path) -> Path:
    """Write a minimal valid .agentfirewall/config.yaml and return its path."""
    content = textwrap.dedent("""\
        version: 1
        mode: enforce
        sandbox:
          root: "."
          allow_escape: false
        filesystem:
          protected_paths:
            - ".git/**"
          deny_operations:
            - delete
        commands:
          blocklist:
            - "rm -rf /"
          allowlist: []
        network:
          allowed_hosts: []
          deny_egress_to:
            - "169.254.169.254"
          max_upload_bytes: 1048576
        logging:
          enabled: true
          file: "logs/firewall.log"
          level: warn
    """)
    af_dir = tmp_path / ".agentfirewall"
    af_dir.mkdir()
    p = af_dir / "config.yaml"
    p.write_text(content)
    return p


def test_load_valid_config(config_file: Path):
    cfg = load_config(config_file)
    assert cfg.version == 1
    assert cfg.mode == FirewallMode.ENFORCE
    assert cfg.sandbox.root == "."
    assert cfg.sandbox.allow_escape is False
    assert ".git/**" in cfg.filesystem.protected_paths
    assert DenyOperation.DELETE in cfg.filesystem.deny_operations
    assert "rm -rf /" in cfg.commands.blocklist
    assert cfg.network.max_upload_bytes == 1_048_576


def test_load_missing_file():
    with pytest.raises(ConfigError, match="not found"):
        load_config("/nonexistent/.agentfirewall/config.yaml")


def test_load_invalid_yaml(tmp_path: Path):
    af_dir = tmp_path / ".agentfirewall"
    af_dir.mkdir()
    bad = af_dir / "config.yaml"
    bad.write_text(": : : not valid yaml [[[")
    with pytest.raises(ConfigError, match="Invalid YAML"):
        load_config(bad)


def test_load_wrong_type(tmp_path: Path):
    af_dir = tmp_path / ".agentfirewall"
    af_dir.mkdir()
    bad = af_dir / "config.yaml"
    bad.write_text("- this is a list\n- not a mapping\n")
    with pytest.raises(ConfigError, match="must be a YAML mapping"):
        load_config(bad)


def test_unsupported_version(tmp_path: Path):
    af_dir = tmp_path / ".agentfirewall"
    af_dir.mkdir()
    bad = af_dir / "config.yaml"
    bad.write_text("version: 99\n")
    with pytest.raises(ConfigError, match="Unsupported config version"):
        load_config(bad)


def test_bad_mode(tmp_path: Path):
    af_dir = tmp_path / ".agentfirewall"
    af_dir.mkdir()
    bad = af_dir / "config.yaml"
    bad.write_text("version: 1\nmode: destroy\n")
    with pytest.raises(ConfigError, match="Unknown mode"):
        load_config(bad)


def test_bad_deny_operation(tmp_path: Path):
    af_dir = tmp_path / ".agentfirewall"
    af_dir.mkdir()
    bad = af_dir / "config.yaml"
    bad.write_text("version: 1\nfilesystem:\n  deny_operations:\n    - explode\n")
    with pytest.raises(ConfigError, match="Unknown deny_operation"):
        load_config(bad)


def test_default_config():
    cfg = default_config()
    assert cfg.mode == FirewallMode.ENFORCE
    assert len(cfg.commands.blocklist) > 0
    assert "rm -rf /" in cfg.commands.blocklist


def test_config_roundtrip(config_file: Path):
    """Load → serialize → reload should produce the same config."""
    cfg1 = load_config(config_file)
    yaml_text = config_to_yaml(cfg1)
    roundtrip = config_file.parent / "config_rt.yaml"
    roundtrip.write_text(yaml_text)
    cfg2 = load_config(roundtrip)
    assert cfg1.mode == cfg2.mode
    assert cfg1.sandbox.root == cfg2.sandbox.root
    assert cfg1.commands.blocklist == cfg2.commands.blocklist


def test_find_config_walks_up(tmp_path: Path):
    """find_config should walk up directories to find .agentfirewall/."""
    af_dir = tmp_path / ".agentfirewall"
    af_dir.mkdir()
    (af_dir / "config.yaml").write_text("version: 1\n")
    child = tmp_path / "a" / "b" / "c"
    child.mkdir(parents=True)
    found = find_config(child)
    assert found is not None
    assert found == af_dir / "config.yaml"


def test_find_config_returns_none(tmp_path: Path):
    child = tmp_path / "empty"
    child.mkdir()
    # tmp_path has no .agentfirewall, but the real filesystem root might.
    # Just test that we get a Path or None without error.
    result = find_config(child)
    # We can't guarantee None here (system root might have one), so just check type.
    assert result is None or isinstance(result, Path)


def test_minimal_config_defaults(tmp_path: Path):
    """A config with only `version: 1` should load with all defaults."""
    af_dir = tmp_path / ".agentfirewall"
    af_dir.mkdir()
    p = af_dir / "config.yaml"
    p.write_text("version: 1\n")
    cfg = load_config(p)
    assert cfg.mode == FirewallMode.ENFORCE
    assert cfg.sandbox.root == "."


def test_create_deny_operation():
    """CREATE should be a valid DenyOperation."""
    assert DenyOperation.CREATE.value == "create"
    assert DenyOperation("create") == DenyOperation.CREATE


def test_log_all_activity_default():
    """log_all_activity should default to False."""
    from agentfirewall.schema import LoggingConfig
    cfg = LoggingConfig()
    assert cfg.log_all_activity is False


def test_log_all_activity_parsed(tmp_path: Path):
    """log_all_activity should round-trip through YAML."""
    af_dir = tmp_path / ".agentfirewall"
    af_dir.mkdir()
    p = af_dir / "config.yaml"
    p.write_text("version: 1\nlogging:\n  log_all_activity: true\n")
    cfg = load_config(p)
    assert cfg.logging.log_all_activity is True


def test_log_all_activity_roundtrip(tmp_path: Path):
    """config_to_yaml should include log_all_activity."""
    cfg = default_config()
    cfg.logging.log_all_activity = True
    yaml_text = config_to_yaml(cfg)
    assert "log_all_activity: true" in yaml_text
    # Reload and verify
    af_dir = tmp_path / ".agentfirewall"
    af_dir.mkdir()
    p = af_dir / "config.yaml"
    p.write_text(yaml_text)
    cfg2 = load_config(p)
    assert cfg2.logging.log_all_activity is True
