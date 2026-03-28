"""Tests for the CLI commands."""

from pathlib import Path

from click.testing import CliRunner

from agentfirewall.cli import main


runner = CliRunner()


class TestInit:
    def test_init_creates_directory(self, tmp_path: Path):
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(main, ["init"])
            assert result.exit_code == 0
            assert ".agentfirewall" in result.output
            af_dir = Path.cwd() / ".agentfirewall"
            assert af_dir.is_dir()
            assert (af_dir / "config.yaml").is_file()
            assert (af_dir / "rules").is_dir()
            assert (af_dir / "logs").is_dir()
            assert (af_dir / "hooks").is_dir()
            assert (af_dir / "plugins").is_dir()

    def test_init_refuses_overwrite(self, tmp_path: Path):
        with runner.isolated_filesystem(temp_dir=tmp_path):
            af_dir = Path.cwd() / ".agentfirewall"
            af_dir.mkdir()
            (af_dir / "config.yaml").write_text("version: 1\n")
            result = runner.invoke(main, ["init"])
            assert result.exit_code == 1
            assert "already exists" in result.output

    def test_init_force_overwrites(self, tmp_path: Path):
        with runner.isolated_filesystem(temp_dir=tmp_path):
            af_dir = Path.cwd() / ".agentfirewall"
            af_dir.mkdir()
            (af_dir / "config.yaml").write_text("version: 1\n")
            result = runner.invoke(main, ["init", "--force"])
            assert result.exit_code == 0

    def test_init_strict_preset(self, tmp_path: Path):
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(main, ["init", "--preset", "strict"])
            assert result.exit_code == 0
            assert "strict" in result.output

    def test_init_permissive_preset(self, tmp_path: Path):
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(main, ["init", "--preset", "permissive"])
            assert result.exit_code == 0
            assert "permissive" in result.output


class TestCheck:
    def test_check_safe_command(self, tmp_path: Path):
        with runner.isolated_filesystem(temp_dir=tmp_path):
            runner.invoke(main, ["init"])
            result = runner.invoke(main, ["check", "ls -la"])
            assert result.exit_code == 0
            assert "ALLOW" in result.output

    def test_check_blocked_command(self, tmp_path: Path):
        with runner.isolated_filesystem(temp_dir=tmp_path):
            runner.invoke(main, ["init"])
            result = runner.invoke(main, ["check", "rm -rf /"])
            assert result.exit_code == 1
            assert "DENY" in result.output

    def test_check_no_config(self, tmp_path: Path):
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(main, ["check", "ls"])
            assert result.exit_code == 1
            assert "No .agentfirewall/" in result.output


class TestStatus:
    def test_status_with_config(self, tmp_path: Path):
        with runner.isolated_filesystem(temp_dir=tmp_path):
            runner.invoke(main, ["init"])
            result = runner.invoke(main, ["status"])
            assert result.exit_code == 0
            assert "Mode:" in result.output
            assert "enforce" in result.output

    def test_status_no_config(self, tmp_path: Path):
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(main, ["status"])
            assert result.exit_code == 0
            assert "No .agentfirewall/" in result.output


class TestCheckFile:
    def test_check_delete_git_blocked(self, tmp_path: Path):
        with runner.isolated_filesystem(temp_dir=tmp_path):
            runner.invoke(main, ["init"])
            result = runner.invoke(main, ["check-file", ".git/HEAD"])
            assert result.exit_code == 1
            assert "DENY" in result.output

    def test_check_delete_regular_allowed(self, tmp_path: Path):
        with runner.isolated_filesystem(temp_dir=tmp_path):
            runner.invoke(main, ["init"])
            result = runner.invoke(main, ["check-file", "output.txt"])
            assert result.exit_code == 0
            assert "ALLOW" in result.output


class TestCheckNetwork:
    def test_check_allowed_host(self, tmp_path: Path):
        with runner.isolated_filesystem(temp_dir=tmp_path):
            runner.invoke(main, ["init"])
            result = runner.invoke(main, ["check-network", "github.com"])
            assert result.exit_code == 0
            assert "ALLOW" in result.output

    def test_check_denied_host(self, tmp_path: Path):
        with runner.isolated_filesystem(temp_dir=tmp_path):
            runner.invoke(main, ["init"])
            result = runner.invoke(main, ["check-network", "169.254.169.254"])
            assert result.exit_code == 1
            assert "DENY" in result.output
