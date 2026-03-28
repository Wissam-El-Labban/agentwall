"""Tests for the protect and unprotect CLI commands."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from agentfirewall.cli import main


class TestProtectCommand:
    def test_protect_creates_dotfile_dir(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("agentfirewall.hooks.shell.install_hook", return_value=Path("~/.bashrc")):
                with patch("subprocess.Popen") as mock_popen:
                    mock_popen.return_value.pid = 12345
                    result = runner.invoke(main, ["protect"])
            assert result.exit_code == 0
            assert (Path.cwd() / ".agentfirewall").exists()

    def test_protect_creates_subdirs(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("agentfirewall.hooks.shell.install_hook", return_value=Path("~/.bashrc")):
                with patch("subprocess.Popen") as mock_popen:
                    mock_popen.return_value.pid = 12345
                    runner.invoke(main, ["protect"])
            base = Path.cwd() / ".agentfirewall"
            for subdir in ["rules", "logs", "hooks", "plugins"]:
                assert (base / subdir).exists()

    def test_protect_writes_config(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("agentfirewall.hooks.shell.install_hook", return_value=Path("~/.bashrc")):
                with patch("subprocess.Popen") as mock_popen:
                    mock_popen.return_value.pid = 12345
                    runner.invoke(main, ["protect"])
            config = Path.cwd() / ".agentfirewall" / "config.yaml"
            assert config.exists()
            assert "enforce" in config.read_text()

    def test_protect_writes_pid_file(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("agentfirewall.hooks.shell.install_hook", return_value=Path("~/.bashrc")):
                with patch("subprocess.Popen") as mock_popen:
                    mock_popen.return_value.pid = 99999
                    runner.invoke(main, ["protect"])
            pid_file = Path.cwd() / ".agentfirewall" / "watcher.pid"
            assert pid_file.exists()
            assert pid_file.read_text().strip() == "99999"

    def test_protect_output_messages(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("agentfirewall.hooks.shell.install_hook", return_value=Path("~/.bashrc")):
                with patch("subprocess.Popen") as mock_popen:
                    mock_popen.return_value.pid = 12345
                    result = runner.invoke(main, ["protect"])
        assert "Initialized" in result.output
        assert "hooks installed" in result.output.lower()
        assert "Watcher running" in result.output
        assert "Protection active" in result.output

    def test_protect_fails_if_already_exists(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            (Path.cwd() / ".agentfirewall").mkdir()
            result = runner.invoke(main, ["protect"])
        assert result.exit_code == 1
        assert "already exists" in result.output

    def test_protect_force_overwrites(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            (Path.cwd() / ".agentfirewall").mkdir()
            with patch("agentfirewall.hooks.shell.install_hook", return_value=Path("~/.bashrc")):
                with patch("subprocess.Popen") as mock_popen:
                    mock_popen.return_value.pid = 12345
                    result = runner.invoke(main, ["protect", "--force"])
        assert result.exit_code == 0

    def test_protect_strict_preset(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("agentfirewall.hooks.shell.install_hook", return_value=Path("~/.bashrc")):
                with patch("subprocess.Popen") as mock_popen:
                    mock_popen.return_value.pid = 12345
                    result = runner.invoke(main, ["protect", "--preset", "strict"])
        assert "strict" in result.output


class TestUnprotectCommand:
    def test_unprotect_stops_watcher(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            base = Path.cwd() / ".agentfirewall"
            base.mkdir()
            pid_file = base / "watcher.pid"
            pid_file.write_text("12345")

            with patch("agentfirewall.hooks.shell.uninstall_hook", return_value=True):
                with patch("os.kill") as mock_kill:
                    result = runner.invoke(main, ["unprotect"])
                    mock_kill.assert_called_once()

        assert result.exit_code == 0
        assert "stopped" in result.output.lower()

    def test_unprotect_removes_pid_file(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            base = Path.cwd() / ".agentfirewall"
            base.mkdir()
            pid_file = base / "watcher.pid"
            pid_file.write_text("12345")

            with patch("agentfirewall.hooks.shell.uninstall_hook", return_value=True):
                with patch("os.kill"):
                    runner.invoke(main, ["unprotect"])

            assert not pid_file.exists()

    def test_unprotect_handles_missing_pid_file(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            (Path.cwd() / ".agentfirewall").mkdir()
            with patch("agentfirewall.hooks.shell.uninstall_hook", return_value=True):
                result = runner.invoke(main, ["unprotect"])
        assert result.exit_code == 0
        assert "No watcher PID" in result.output

    def test_unprotect_handles_dead_process(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            base = Path.cwd() / ".agentfirewall"
            base.mkdir()
            (base / "watcher.pid").write_text("99999")

            with patch("agentfirewall.hooks.shell.uninstall_hook", return_value=True):
                with patch("os.kill", side_effect=ProcessLookupError):
                    result = runner.invoke(main, ["unprotect"])

        assert result.exit_code == 0
        assert "already stopped" in result.output.lower() or "not found" in result.output.lower()

    def test_unprotect_removes_config_with_flag(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            base = Path.cwd() / ".agentfirewall"
            base.mkdir()

            with patch("agentfirewall.hooks.shell.uninstall_hook", return_value=True):
                with patch("os.kill"):
                    runner.invoke(main, ["unprotect", "--remove-config"])

            assert not base.exists()

    def test_unprotect_output_messages(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            base = Path.cwd() / ".agentfirewall"
            base.mkdir()
            (base / "watcher.pid").write_text("12345")

            with patch("agentfirewall.hooks.shell.uninstall_hook", return_value=True):
                with patch("os.kill"):
                    result = runner.invoke(main, ["unprotect"])

        assert "Protection disabled" in result.output
