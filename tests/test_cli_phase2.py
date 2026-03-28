"""Tests for Phase 2 CLI commands: watch, install-hooks, uninstall-hooks."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from agentfirewall.cli import main
from agentfirewall.schema import DOTFILE_NAME, CONFIG_FILENAME, SUBDIRS, config_to_yaml
from agentfirewall.presets import get_preset


def _init_dotfile(base: Path, preset: str = "standard") -> None:
    """Create a .agentfirewall/ directory with config for testing."""
    target = base / DOTFILE_NAME
    target.mkdir()
    for sub in SUBDIRS:
        (target / sub).mkdir()
    config = get_preset(preset)
    (target / CONFIG_FILENAME).write_text(config_to_yaml(config), encoding="utf-8")


class TestWatch:
    @patch("agentfirewall.watchers.filesystem.FirewallObserver")
    def test_watch_starts_observer(self, mock_observer_cls):
        runner = CliRunner()
        with runner.isolated_filesystem() as td:
            _init_dotfile(Path(td))
            mock_obs = MagicMock()
            mock_observer_cls.return_value = mock_obs

            result = runner.invoke(main, ["watch"])
            assert "Watching" in result.output
            mock_obs.run_forever.assert_called_once()

    def test_watch_no_config(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(main, ["watch"])
            assert result.exit_code == 1
            assert "No .agentfirewall/" in result.output


class TestInstallHooks:
    def test_install_hooks_bash(self, tmp_path):
        rc = tmp_path / ".bashrc"
        runner = CliRunner()
        with patch("agentfirewall.hooks.shell._rc_path_for_shell", return_value=rc):
            result = runner.invoke(main, ["install-hooks", "--shell", "bash"])
            assert result.exit_code == 0
            assert "Hooks installed" in result.output
            assert rc.exists()
            assert "agentfirewall" in rc.read_text()

    def test_install_hooks_zsh(self, tmp_path):
        rc = tmp_path / ".zshrc"
        runner = CliRunner()
        with patch("agentfirewall.hooks.shell._rc_path_for_shell", return_value=rc):
            result = runner.invoke(main, ["install-hooks", "--shell", "zsh"])
            assert result.exit_code == 0
            assert "add-zsh-hook" in rc.read_text()


class TestUninstallHooks:
    def test_uninstall_hooks_removes(self, tmp_path):
        rc = tmp_path / ".bashrc"
        runner = CliRunner()
        with patch("agentfirewall.hooks.shell._rc_path_for_shell", return_value=rc):
            runner.invoke(main, ["install-hooks", "--shell", "bash"])
            result = runner.invoke(main, ["uninstall-hooks", "--shell", "bash"])
            assert result.exit_code == 0
            assert "Hooks removed" in result.output
            assert "agentfirewall" not in rc.read_text()

    def test_uninstall_hooks_not_present(self, tmp_path):
        rc = tmp_path / ".bashrc"
        rc.write_text("# empty\n")
        runner = CliRunner()
        with patch("agentfirewall.hooks.shell._rc_path_for_shell", return_value=rc):
            result = runner.invoke(main, ["uninstall-hooks", "--shell", "bash"])
            assert result.exit_code == 0
            assert "No hooks found" in result.output
