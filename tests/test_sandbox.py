"""Tests for the FUSE sandbox module."""

from __future__ import annotations

import errno
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agentfirewall.engine import Engine, RuleResult, Verdict
from agentfirewall.schema import (
    DenyOperation,
    FirewallConfig,
    FilesystemConfig,
    FirewallMode,
    SandboxConfig,
)


# ── helpers ─────────────────────────────────────────────────────


def _make_config(
    protected: list[str] | None = None,
    deny_ops: list[DenyOperation] | None = None,
    sandbox_root: str = ".",
    mode: FirewallMode = FirewallMode.ENFORCE,
) -> FirewallConfig:
    return FirewallConfig(
        mode=mode,
        sandbox=SandboxConfig(root=sandbox_root),
        filesystem=FilesystemConfig(
            protected_paths=protected or [".git/**", ".env", ".agentfirewall/**"],
            deny_operations=deny_ops or [
                DenyOperation.DELETE,
                DenyOperation.WRITE,
                DenyOperation.MOVE_OUTSIDE_SANDBOX,
                DenyOperation.CHMOD,
            ],
        ),
    )


def _make_fs(tmp_path: Path, config: FirewallConfig | None = None):
    """Create a FirewallFS instance backed by tmp_path."""
    from agentfirewall.sandbox import FirewallFS

    if config is None:
        config = _make_config(sandbox_root=str(tmp_path))
    engine = Engine(config)
    return FirewallFS(tmp_path, engine)


# ── FirewallFS unit tests ───────────────────────────────────────


class TestFirewallFSPathHelpers:
    def test_real_path_translation(self, tmp_path):
        fs = _make_fs(tmp_path)
        assert fs._real("/some/file.txt") == str(tmp_path / "some" / "file.txt")

    def test_real_path_no_leading_slash(self, tmp_path):
        fs = _make_fs(tmp_path)
        assert fs._real("file.txt") == str(tmp_path / "file.txt")

    def test_rel_strips_leading_slash(self, tmp_path):
        fs = _make_fs(tmp_path)
        assert fs._rel("/some/file") == "some/file"
        assert fs._rel("some/file") == "some/file"

    def test_is_firewall_dir_detects_config_dir(self, tmp_path):
        fs = _make_fs(tmp_path)
        assert fs._is_firewall_dir("/.agentfirewall") is True
        assert fs._is_firewall_dir("/.agentfirewall/config.yaml") is True
        assert fs._is_firewall_dir(".agentfirewall") is True
        assert fs._is_firewall_dir(".agentfirewall/logs/firewall.log") is True

    def test_is_firewall_dir_ignores_others(self, tmp_path):
        fs = _make_fs(tmp_path)
        assert fs._is_firewall_dir("/src/main.py") is False
        assert fs._is_firewall_dir("/.git/config") is False
        assert fs._is_firewall_dir("/.agentfirewallx") is False


class TestFirewallFSReadOps:
    def test_getattr_returns_stat_dict(self, tmp_path):
        (tmp_path / "hello.txt").write_text("hi")
        fs = _make_fs(tmp_path)
        attrs = fs.getattr("/hello.txt")
        assert "st_size" in attrs
        assert attrs["st_size"] == 2
        # use_ns=True: time fields are nanosecond ints
        assert isinstance(attrs["st_mtime"], int)
        assert attrs["st_mtime"] > 0

    def test_readdir_lists_entries(self, tmp_path):
        (tmp_path / "a.txt").touch()
        (tmp_path / "b.txt").touch()
        fs = _make_fs(tmp_path)
        entries = fs.readdir("/")
        assert "." in entries
        assert ".." in entries
        assert "a.txt" in entries
        assert "b.txt" in entries

    def test_statfs_returns_dict(self, tmp_path):
        fs = _make_fs(tmp_path)
        result = fs.statfs("/")
        assert "f_bsize" in result

    def test_access_check(self, tmp_path):
        (tmp_path / "readable.txt").write_text("data")
        fs = _make_fs(tmp_path)
        assert fs.access("/readable.txt", os.R_OK) == 0


class TestFirewallFSOpenReadRelease:
    def test_open_read_release_cycle(self, tmp_path):
        (tmp_path / "data.txt").write_text("hello world")
        fs = _make_fs(tmp_path)

        fh = fs.open("/data.txt", os.O_RDONLY)
        data = fs.read("/data.txt", 11, 0, fh)
        assert data == b"hello world"
        fs.release("/data.txt", fh)

    def test_open_for_write_on_allowed_path(self, tmp_path):
        (tmp_path / "safe.txt").write_text("ok")
        fs = _make_fs(tmp_path)
        fh = fs.open("/safe.txt", os.O_WRONLY)
        fs.release("/safe.txt", fh)

    def test_open_for_write_on_firewall_dir_blocked(self, tmp_path):
        fw_dir = tmp_path / ".agentfirewall"
        fw_dir.mkdir()
        (fw_dir / "config.yaml").write_text("version: 1")
        fs = _make_fs(tmp_path)

        with pytest.raises(OSError) as exc_info:
            fs.open("/.agentfirewall/config.yaml", os.O_WRONLY)
        assert exc_info.value.errno == errno.EACCES

    def test_open_for_write_on_protected_path_blocked(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("core")
        config = _make_config(
            sandbox_root=str(tmp_path),
            protected=[".git/**"],
            deny_ops=[DenyOperation.WRITE],
        )
        fs = _make_fs(tmp_path, config)

        with pytest.raises(OSError) as exc_info:
            fs.open("/.git/config", os.O_WRONLY)
        assert exc_info.value.errno == errno.EACCES


class TestFirewallFSUnlink:
    def test_unlink_protected_path_blocked(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        target = git_dir / "HEAD"
        target.write_text("ref: refs/heads/main")
        fs = _make_fs(tmp_path)

        with pytest.raises(OSError) as exc_info:
            fs.unlink("/.git/HEAD")
        assert exc_info.value.errno == errno.EACCES
        # Real file untouched
        assert target.exists()
        assert target.read_text() == "ref: refs/heads/main"

    def test_unlink_allowed_path_succeeds(self, tmp_path):
        target = tmp_path / "temp.txt"
        target.write_text("disposable")
        fs = _make_fs(tmp_path)

        fs.unlink("/temp.txt")
        assert not target.exists()

    def test_unlink_firewall_dir_blocked(self, tmp_path):
        fw_dir = tmp_path / ".agentfirewall"
        fw_dir.mkdir()
        target = fw_dir / "config.yaml"
        target.write_text("version: 1")
        fs = _make_fs(tmp_path)

        with pytest.raises(OSError) as exc_info:
            fs.unlink("/.agentfirewall/config.yaml")
        assert exc_info.value.errno == errno.EACCES
        assert target.exists()


class TestFirewallFSWrite:
    def test_write_to_allowed_path(self, tmp_path):
        target = tmp_path / "output.txt"
        target.write_text("")
        fs = _make_fs(tmp_path)

        fh = fs.open("/output.txt", os.O_WRONLY)
        written = fs.write("/output.txt", b"data", 0, fh)
        assert written == 4
        fs.release("/output.txt", fh)

    def test_write_first_write_evaluation(self, tmp_path):
        """First write on a handle opened without write flags evaluates the engine."""
        target = tmp_path / "test.txt"
        target.write_text("original")
        config = _make_config(
            sandbox_root=str(tmp_path),
            protected=[".env"],
            deny_ops=[DenyOperation.WRITE],
        )
        fs = _make_fs(tmp_path, config)

        # .env is protected for writes
        env_file = tmp_path / ".env"
        env_file.write_text("SECRET=x")

        with pytest.raises(OSError) as exc_info:
            # create opens for write — should be blocked on protected file
            fs.create("/.env", 0o644)
        assert exc_info.value.errno == errno.EACCES

    def test_write_to_firewall_dir_blocked_via_write(self, tmp_path):
        fw_dir = tmp_path / ".agentfirewall"
        fw_dir.mkdir()
        target = fw_dir / "config.yaml"
        target.write_text("version: 1")
        fs = _make_fs(tmp_path)

        with pytest.raises(OSError) as exc_info:
            fs.open("/.agentfirewall/config.yaml", os.O_WRONLY)
        assert exc_info.value.errno == errno.EACCES

    def test_truncate_protected_path_blocked(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("SECRET=value")
        config = _make_config(
            sandbox_root=str(tmp_path),
            protected=[".env"],
            deny_ops=[DenyOperation.WRITE],
        )
        fs = _make_fs(tmp_path, config)

        with pytest.raises(OSError) as exc_info:
            fs.truncate("/.env", 0)
        assert exc_info.value.errno == errno.EACCES
        assert env_file.read_text() == "SECRET=value"

    def test_truncate_allowed_path(self, tmp_path):
        target = tmp_path / "safe.txt"
        target.write_text("long content here")
        fs = _make_fs(tmp_path)

        fs.truncate("/safe.txt", 4)
        assert target.read_text() == "long"


class TestFirewallFSRmdir:
    def test_rmdir_firewall_dir_blocked(self, tmp_path):
        fw_dir = tmp_path / ".agentfirewall"
        fw_dir.mkdir()
        fs = _make_fs(tmp_path)

        with pytest.raises(OSError) as exc_info:
            fs.rmdir("/.agentfirewall")
        assert exc_info.value.errno == errno.EACCES

    def test_rmdir_allowed_directory(self, tmp_path):
        target = tmp_path / "emptydir"
        target.mkdir()
        fs = _make_fs(tmp_path)

        fs.rmdir("/emptydir")
        assert not target.exists()


class TestFirewallFSRename:
    def test_rename_from_firewall_dir_blocked(self, tmp_path):
        fw_dir = tmp_path / ".agentfirewall"
        fw_dir.mkdir()
        (fw_dir / "config.yaml").write_text("v1")
        fs = _make_fs(tmp_path)

        with pytest.raises(OSError) as exc_info:
            fs.rename("/.agentfirewall/config.yaml", "/stolen.yaml")
        assert exc_info.value.errno == errno.EACCES

    def test_rename_to_firewall_dir_blocked(self, tmp_path):
        fw_dir = tmp_path / ".agentfirewall"
        fw_dir.mkdir()
        (tmp_path / "evil.yaml").write_text("mode: off")
        fs = _make_fs(tmp_path)

        with pytest.raises(OSError) as exc_info:
            fs.rename("/evil.yaml", "/.agentfirewall/config.yaml")
        assert exc_info.value.errno == errno.EACCES

    def test_rename_allowed_paths(self, tmp_path):
        (tmp_path / "old.txt").write_text("data")
        fs = _make_fs(tmp_path)

        fs.rename("/old.txt", "/new.txt")
        assert not (tmp_path / "old.txt").exists()
        assert (tmp_path / "new.txt").read_text() == "data"


class TestFirewallFSChmod:
    def test_chmod_protected_path_blocked(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        target = git_dir / "HEAD"
        target.write_text("ref")
        config = _make_config(
            sandbox_root=str(tmp_path),
            protected=[".git/**"],
            deny_ops=[DenyOperation.CHMOD],
        )
        fs = _make_fs(tmp_path, config)

        with pytest.raises(OSError) as exc_info:
            fs.chmod("/.git/HEAD", 0o777)
        assert exc_info.value.errno == errno.EACCES

    def test_chmod_allowed_path(self, tmp_path):
        target = tmp_path / "script.sh"
        target.write_text("#!/bin/bash")
        fs = _make_fs(tmp_path)

        fs.chmod("/script.sh", 0o755)
        assert os.stat(str(target)).st_mode & 0o777 == 0o755

    def test_chmod_firewall_dir_blocked(self, tmp_path):
        fw_dir = tmp_path / ".agentfirewall"
        fw_dir.mkdir()
        fs = _make_fs(tmp_path)

        with pytest.raises(OSError) as exc_info:
            fs.chmod("/.agentfirewall", 0o777)
        assert exc_info.value.errno == errno.EACCES


class TestFirewallFSCreate:
    def test_create_in_firewall_dir_blocked(self, tmp_path):
        fw_dir = tmp_path / ".agentfirewall"
        fw_dir.mkdir()
        fs = _make_fs(tmp_path)

        with pytest.raises(OSError) as exc_info:
            fs.create("/.agentfirewall/evil.txt", 0o644)
        assert exc_info.value.errno == errno.EACCES

    def test_create_allowed_path(self, tmp_path):
        fs = _make_fs(tmp_path)
        fh = fs.create("/newfile.txt", 0o644)
        fs.write("/newfile.txt", b"hello", 0, fh)
        fs.release("/newfile.txt", fh)
        assert (tmp_path / "newfile.txt").read_text() == "hello"


class TestFirewallFSMkdirSymlinkLink:
    def test_mkdir_in_firewall_dir_blocked(self, tmp_path):
        fw_dir = tmp_path / ".agentfirewall"
        fw_dir.mkdir()
        fs = _make_fs(tmp_path)

        with pytest.raises(OSError) as exc_info:
            fs.mkdir("/.agentfirewall/subdir", 0o755)
        assert exc_info.value.errno == errno.EACCES

    def test_mkdir_allowed(self, tmp_path):
        fs = _make_fs(tmp_path)
        fs.mkdir("/newdir", 0o755)
        assert (tmp_path / "newdir").is_dir()

    def test_symlink_in_firewall_dir_blocked(self, tmp_path):
        fw_dir = tmp_path / ".agentfirewall"
        fw_dir.mkdir()
        fs = _make_fs(tmp_path)

        with pytest.raises(OSError) as exc_info:
            fs.symlink("/some/target", "/.agentfirewall/link")
        assert exc_info.value.errno == errno.EACCES

    def test_link_in_firewall_dir_blocked(self, tmp_path):
        fw_dir = tmp_path / ".agentfirewall"
        fw_dir.mkdir()
        (tmp_path / "source.txt").write_text("data")
        fs = _make_fs(tmp_path)

        with pytest.raises(OSError) as exc_info:
            fs.link("/source.txt", "/.agentfirewall/hardlink")
        assert exc_info.value.errno == errno.EACCES


class TestFirewallFSModeOff:
    def test_mode_off_allows_protected_delete(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        target = git_dir / "HEAD"
        target.write_text("ref")
        config = _make_config(
            sandbox_root=str(tmp_path),
            mode=FirewallMode.OFF,
        )
        fs = _make_fs(tmp_path, config)

        # Engine returns ALLOW when mode is off, so unlink should succeed
        # But .agentfirewall/ self-protection is *independent* of engine mode
        fs.unlink("/.git/HEAD")
        assert not target.exists()


class TestFirewallFSSelfProtectionIndependentOfMode:
    def test_firewall_dir_blocked_even_when_off(self, tmp_path):
        """Self-protection of .agentfirewall/ is hardcoded, not engine-dependent."""
        fw_dir = tmp_path / ".agentfirewall"
        fw_dir.mkdir()
        target = fw_dir / "config.yaml"
        target.write_text("version: 1")
        config = _make_config(
            sandbox_root=str(tmp_path),
            mode=FirewallMode.OFF,
        )
        fs = _make_fs(tmp_path, config)

        with pytest.raises(OSError) as exc_info:
            fs.unlink("/.agentfirewall/config.yaml")
        assert exc_info.value.errno == errno.EACCES
        assert target.exists()


# ── lifecycle / helper tests ────────────────────────────────────


class TestMountHelpers:
    def test_default_mountpoint_deterministic(self, tmp_path):
        from agentfirewall.sandbox import _default_mountpoint

        mp1 = _default_mountpoint(tmp_path)
        mp2 = _default_mountpoint(tmp_path)
        assert mp1 == mp2
        assert "agentfirewall-" in str(mp1)

    def test_default_mountpoint_different_for_different_sources(self, tmp_path):
        from agentfirewall.sandbox import _default_mountpoint

        mp1 = _default_mountpoint(tmp_path / "project1")
        mp2 = _default_mountpoint(tmp_path / "project2")
        assert mp1 != mp2

    def test_require_fusepy_raises_when_missing(self):
        from agentfirewall.sandbox import _require_fusepy

        with patch("agentfirewall.sandbox.fuse", None):
            with pytest.raises(RuntimeError, match="fusepy is required"):
                _require_fusepy()

    def test_require_fusepy_noop_when_available(self):
        from agentfirewall.sandbox import _require_fusepy

        # Should not raise when fuse module is available (or mocked as truthy)
        with patch("agentfirewall.sandbox.fuse", MagicMock()):
            _require_fusepy()

    def test_unmount_returns_false_for_nonexistent_path(self, tmp_path):
        from agentfirewall.sandbox import unmount

        result = unmount(tmp_path / "nonexistent-mount-12345")
        assert result is False

    def test_unmount_calls_fusermount(self, tmp_path):
        from agentfirewall.sandbox import unmount

        target = tmp_path / "fake-mount"
        target.mkdir()

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = unmount(target)
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert args[0] == "fusermount"
            assert args[1] == "-u"
            assert str(target) in args[2]

    def test_is_mounted_false_for_regular_dir(self, tmp_path):
        from agentfirewall.sandbox import is_mounted

        # A regular directory should not be a FUSE mount
        assert is_mounted(tmp_path) is False


class TestOperationMapping:
    def test_op_mappings(self):
        from agentfirewall.sandbox import (
            _op_for_chmod,
            _op_for_rename,
            _op_for_rmdir,
            _op_for_truncate,
            _op_for_unlink,
            _op_for_write,
        )

        assert _op_for_unlink() == DenyOperation.DELETE
        assert _op_for_rmdir() == DenyOperation.DELETE
        assert _op_for_write() == DenyOperation.WRITE
        assert _op_for_truncate() == DenyOperation.WRITE
        assert _op_for_chmod() == DenyOperation.CHMOD
        assert _op_for_rename() == DenyOperation.MOVE_OUTSIDE_SANDBOX


# ── CLI integration tests ──────────────────────────────────────


class TestSandboxCLI:
    def test_sandbox_command_exists(self):
        from click.testing import CliRunner
        from agentfirewall.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["sandbox", "--help"])
        assert result.exit_code == 0
        assert "FUSE sandbox" in result.output or "sandbox" in result.output

    def test_sandbox_no_config_exits_with_error(self, tmp_path):
        from click.testing import CliRunner
        from agentfirewall.cli import main

        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("agentfirewall.cli.find_config", return_value=None):
                result = runner.invoke(main, ["sandbox"])
                assert result.exit_code != 0
                assert "No .agentfirewall/" in result.output or result.exit_code == 1
