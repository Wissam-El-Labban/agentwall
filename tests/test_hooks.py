"""Tests for shell preexec hook generation and installation."""

from pathlib import Path
from unittest.mock import patch

import pytest

from agentfirewall.hooks.shell import (
    GUARD_BEGIN,
    GUARD_END,
    detect_shell,
    generate_bash_hook,
    generate_zsh_hook,
    install_hook,
    uninstall_hook,
)


class TestGenerate:
    def test_bash_hook_has_guard_markers(self):
        hook = generate_bash_hook()
        assert GUARD_BEGIN in hook
        assert GUARD_END in hook

    def test_bash_hook_has_trap(self):
        hook = generate_bash_hook()
        assert "trap" in hook
        assert "DEBUG" in hook
        assert "agentfirewall check" in hook

    def test_bash_hook_enables_extdebug(self):
        hook = generate_bash_hook()
        assert "shopt -s extdebug" in hook

    def test_zsh_hook_has_guard_markers(self):
        hook = generate_zsh_hook()
        assert GUARD_BEGIN in hook
        assert GUARD_END in hook

    def test_zsh_hook_has_preexec(self):
        hook = generate_zsh_hook()
        assert "add-zsh-hook" in hook
        assert "preexec" in hook
        assert "agentfirewall check" in hook

    def test_zsh_hook_aborts_with_sigint(self):
        hook = generate_zsh_hook()
        assert "kill -INT $$" in hook


class TestDetectShell:
    @patch.dict("os.environ", {"SHELL": "/bin/zsh"})
    def test_detects_zsh(self):
        assert detect_shell() == "zsh"

    @patch.dict("os.environ", {"SHELL": "/bin/bash"})
    def test_detects_bash(self):
        assert detect_shell() == "bash"

    @patch.dict("os.environ", {"SHELL": "/usr/local/bin/zsh"})
    def test_detects_zsh_full_path(self):
        assert detect_shell() == "zsh"

    @patch.dict("os.environ", {"SHELL": ""})
    def test_defaults_to_bash(self):
        assert detect_shell() == "bash"


class TestInstallHook:
    def test_installs_to_new_file(self, tmp_path):
        rc = tmp_path / ".bashrc"
        result = install_hook(shell="bash", rc_path=rc)
        assert result == rc
        content = rc.read_text()
        assert GUARD_BEGIN in content
        assert "trap" in content

    def test_appends_to_existing_file(self, tmp_path):
        rc = tmp_path / ".bashrc"
        rc.write_text("# existing config\nalias ll='ls -la'\n")
        install_hook(shell="bash", rc_path=rc)
        content = rc.read_text()
        assert content.startswith("# existing config")
        assert GUARD_BEGIN in content

    def test_idempotent_no_duplicate(self, tmp_path):
        rc = tmp_path / ".bashrc"
        install_hook(shell="bash", rc_path=rc)
        install_hook(shell="bash", rc_path=rc)
        content = rc.read_text()
        assert content.count(GUARD_BEGIN) == 1

    def test_installs_zsh_hook(self, tmp_path):
        rc = tmp_path / ".zshrc"
        install_hook(shell="zsh", rc_path=rc)
        content = rc.read_text()
        assert "add-zsh-hook" in content

    def test_returns_rc_path(self, tmp_path):
        rc = tmp_path / ".bashrc"
        result = install_hook(shell="bash", rc_path=rc)
        assert result == rc


class TestUninstallHook:
    def test_removes_hook_block(self, tmp_path):
        rc = tmp_path / ".bashrc"
        install_hook(shell="bash", rc_path=rc)
        assert GUARD_BEGIN in rc.read_text()

        removed = uninstall_hook(shell="bash", rc_path=rc)
        assert removed is True
        assert GUARD_BEGIN not in rc.read_text()
        assert GUARD_END not in rc.read_text()

    def test_preserves_surrounding_content(self, tmp_path):
        rc = tmp_path / ".bashrc"
        rc.write_text("# before\n")
        install_hook(shell="bash", rc_path=rc)
        rc.write_text(rc.read_text() + "# after\n")

        uninstall_hook(shell="bash", rc_path=rc)
        content = rc.read_text()
        assert "# before" in content
        assert "# after" in content
        assert GUARD_BEGIN not in content

    def test_returns_false_when_not_present(self, tmp_path):
        rc = tmp_path / ".bashrc"
        rc.write_text("# just a normal bashrc\n")
        assert uninstall_hook(shell="bash", rc_path=rc) is False

    def test_returns_false_when_file_missing(self, tmp_path):
        rc = tmp_path / ".bashrc"
        assert uninstall_hook(shell="bash", rc_path=rc) is False
