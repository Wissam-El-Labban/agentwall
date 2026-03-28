"""Tests for built-in presets."""

from agentfirewall.presets import get_preset, list_presets
from agentfirewall.schema import FirewallMode

import pytest


def test_list_presets():
    names = list_presets()
    assert "standard" in names
    assert "strict" in names
    assert "permissive" in names


def test_standard_preset():
    cfg = get_preset("standard")
    assert cfg.mode == FirewallMode.ENFORCE
    assert len(cfg.commands.blocklist) > 0
    assert cfg.sandbox.allow_escape is False


def test_strict_preset():
    cfg = get_preset("strict")
    assert cfg.mode == FirewallMode.ENFORCE
    # Strict has more blocklist entries than standard
    std = get_preset("standard")
    assert len(cfg.commands.blocklist) > len(std.commands.blocklist)


def test_permissive_preset():
    cfg = get_preset("permissive")
    assert cfg.mode == FirewallMode.AUDIT
    assert cfg.sandbox.allow_escape is True


def test_unknown_preset_raises():
    with pytest.raises(ValueError, match="Unknown preset"):
        get_preset("nonexistent")
