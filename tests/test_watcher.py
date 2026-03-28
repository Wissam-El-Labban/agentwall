"""Tests for the filesystem watcher module."""

import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from watchdog.events import FileDeletedEvent, FileModifiedEvent, FileMovedEvent, DirDeletedEvent

from agentfirewall.engine import Engine, Verdict
from agentfirewall.schema import DenyOperation, FirewallConfig, FilesystemConfig, SandboxConfig
from agentfirewall.watchers.filesystem import FirewallHandler, FirewallObserver


def _make_config(protected=None, sandbox_root=".") -> FirewallConfig:
    return FirewallConfig(
        sandbox=SandboxConfig(root=sandbox_root),
        filesystem=FilesystemConfig(
            protected_paths=protected or [".git/**", ".env"],
            deny_operations=[DenyOperation.DELETE, DenyOperation.WRITE, DenyOperation.MOVE_OUTSIDE_SANDBOX],
        ),
    )


class TestFirewallHandler:
    def test_delete_protected_path_triggers_deny(self, tmp_path):
        config = _make_config(sandbox_root=str(tmp_path))
        engine = Engine(config)
        handler = FirewallHandler(engine, tmp_path / ".agentfirewall")

        event = FileDeletedEvent(str(tmp_path / ".git" / "config"))
        handler.on_deleted(event)
        # No crash — the handler processes the event

    def test_modify_protected_path_triggers_deny(self, tmp_path):
        config = _make_config(sandbox_root=str(tmp_path))
        engine = Engine(config)
        handler = FirewallHandler(engine, tmp_path / ".agentfirewall")

        event = FileModifiedEvent(str(tmp_path / ".env"))
        handler.on_modified(event)

    def test_ignores_events_inside_agentfirewall_dir(self, tmp_path):
        config = _make_config(sandbox_root=str(tmp_path))
        engine = Engine(config)
        base_dir = tmp_path / ".agentfirewall"
        base_dir.mkdir()
        handler = FirewallHandler(engine, base_dir)

        # This should be silently ignored
        event = FileModifiedEvent(str(base_dir / "logs" / "firewall.log"))
        handler.on_modified(event)

    def test_ignores_directory_events(self, tmp_path):
        config = _make_config(sandbox_root=str(tmp_path))
        engine = Engine(config)
        handler = FirewallHandler(engine, tmp_path / ".agentfirewall")

        event = DirDeletedEvent(str(tmp_path / ".git"))
        handler.on_deleted(event)

    def test_allows_normal_file_operations(self, tmp_path):
        config = _make_config(sandbox_root=str(tmp_path))
        engine = Engine(config)
        handler = FirewallHandler(engine, tmp_path / ".agentfirewall")

        event = FileModifiedEvent(str(tmp_path / "README.md"))
        handler.on_modified(event)

    def test_calls_process_killer_on_deny(self, tmp_path):
        config = _make_config(sandbox_root=str(tmp_path))
        engine = Engine(config)
        killer = MagicMock()
        killer.kill_agents.return_value = 1
        handler = FirewallHandler(engine, tmp_path / ".agentfirewall", process_killer=killer)

        event = FileDeletedEvent(str(tmp_path / ".git" / "HEAD"))
        handler.on_deleted(event)
        killer.kill_agents.assert_called_once()

    def test_deny_prints_violation_to_stderr(self, tmp_path, capsys):
        config = _make_config(sandbox_root=str(tmp_path))
        engine = Engine(config)
        handler = FirewallHandler(engine, tmp_path / ".agentfirewall")

        event = FileDeletedEvent(str(tmp_path / ".git" / "HEAD"))
        handler.on_deleted(event)

        captured = capsys.readouterr()
        assert "DENY" in captured.err
        assert "delete" in captured.err.lower()
        assert ".git" in captured.err

    def test_allow_prints_nothing(self, tmp_path, capsys):
        config = _make_config(sandbox_root=str(tmp_path))
        engine = Engine(config)
        handler = FirewallHandler(engine, tmp_path / ".agentfirewall")

        event = FileModifiedEvent(str(tmp_path / "README.md"))
        handler.on_modified(event)

        captured = capsys.readouterr()
        assert captured.err == ""

    def test_deny_prints_killed_count(self, tmp_path, capsys):
        config = _make_config(sandbox_root=str(tmp_path))
        engine = Engine(config)
        killer = MagicMock()
        killer.kill_agents.return_value = 2
        handler = FirewallHandler(engine, tmp_path / ".agentfirewall", process_killer=killer)

        event = FileDeletedEvent(str(tmp_path / ".git" / "HEAD"))
        handler.on_deleted(event)

        captured = capsys.readouterr()
        assert "Killed 2 agent process(es)" in captured.err

    def test_no_killer_call_on_allow(self, tmp_path):
        config = _make_config(sandbox_root=str(tmp_path))
        engine = Engine(config)
        killer = MagicMock()
        handler = FirewallHandler(engine, tmp_path / ".agentfirewall", process_killer=killer)

        event = FileModifiedEvent(str(tmp_path / "README.md"))
        handler.on_modified(event)
        killer.kill_agents.assert_not_called()

    def test_moved_event_evaluates_dest_path(self, tmp_path):
        config = _make_config(sandbox_root=str(tmp_path))
        engine = Engine(config)
        handler = FirewallHandler(engine, tmp_path / ".agentfirewall")

        event = FileMovedEvent(
            str(tmp_path / "temp.txt"),
            str(tmp_path / ".git" / "temp.txt"),
        )
        handler.on_moved(event)


class TestFirewallObserver:
    def test_start_and_stop(self, tmp_path):
        config = _make_config(sandbox_root=str(tmp_path))
        engine = Engine(config)
        observer = FirewallObserver(engine, tmp_path / ".agentfirewall")

        observer.start()
        assert observer._observer is not None
        assert observer._observer.is_alive()

        observer.stop()
        assert observer._observer is None

    def test_detects_file_deletion(self, tmp_path):
        """Integration: start observer, delete a file, verify handler fires."""
        config = _make_config(
            protected=[".git/**"],
            sandbox_root=str(tmp_path),
        )
        engine = Engine(config)
        killer = MagicMock()
        killer.kill_agents.return_value = 0
        observer = FirewallObserver(engine, tmp_path / ".agentfirewall", process_killer=killer)

        # Create a protected file
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        target = git_dir / "HEAD"
        target.write_text("ref: refs/heads/main")

        observer.start()
        try:
            time.sleep(0.3)  # let observer settle
            target.unlink()
            time.sleep(0.5)  # let event propagate
        finally:
            observer.stop()

        killer.kill_agents.assert_called()
