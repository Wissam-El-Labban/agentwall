"""Tests for the process killer module."""

from unittest.mock import MagicMock, patch

import psutil
import pytest

from agentfirewall.process import ProcessKiller, _SAFE_PIDS


def _fake_proc(pid, name, cmdline=None):
    """Create a mock process with the given attributes."""
    proc = MagicMock(spec=psutil.Process)
    proc.info = {"pid": pid, "name": name, "cmdline": cmdline or []}
    proc.pid = pid
    proc.name.return_value = name
    return proc


class TestFindAgentProcesses:
    @patch("agentfirewall.process.psutil.process_iter")
    def test_matches_known_agent_name(self, mock_iter):
        mock_iter.return_value = [_fake_proc(100, "claude")]
        killer = ProcessKiller()
        found = killer.find_agent_processes()
        assert len(found) == 1
        assert found[0].pid == 100

    @patch("agentfirewall.process.psutil.process_iter")
    def test_matches_cursor(self, mock_iter):
        mock_iter.return_value = [_fake_proc(200, "cursor-agent")]
        killer = ProcessKiller()
        found = killer.find_agent_processes()
        assert len(found) == 1

    @patch("agentfirewall.process.psutil.process_iter")
    def test_skips_pid_1(self, mock_iter):
        mock_iter.return_value = [_fake_proc(1, "claude")]
        killer = ProcessKiller()
        assert killer.find_agent_processes() == []

    @patch("agentfirewall.process.psutil.process_iter")
    def test_skips_own_pid(self, mock_iter):
        import os
        mock_iter.return_value = [_fake_proc(os.getpid(), "claude")]
        killer = ProcessKiller()
        assert killer.find_agent_processes() == []

    @patch("agentfirewall.process.psutil.process_iter")
    def test_skips_unrelated_process(self, mock_iter):
        mock_iter.return_value = [_fake_proc(999, "firefox")]
        killer = ProcessKiller()
        assert killer.find_agent_processes() == []

    @patch("agentfirewall.process.psutil.process_iter")
    def test_node_only_matches_with_agent_cmdline(self, mock_iter):
        # Plain node process — should NOT match
        plain_node = _fake_proc(300, "node", ["node", "server.js"])
        # Node running an agent — should match
        agent_node = _fake_proc(301, "node", ["node", "/usr/lib/claude/main.js"])
        mock_iter.return_value = [plain_node, agent_node]
        killer = ProcessKiller()
        found = killer.find_agent_processes()
        assert len(found) == 1
        assert found[0].pid == 301

    @patch("agentfirewall.process.psutil.process_iter")
    def test_handles_no_such_process(self, mock_iter):
        proc = MagicMock(spec=psutil.Process)
        proc.info = {"pid": 100, "name": "claude", "cmdline": []}
        # Make accessing info raise NoSuchProcess
        type(proc).info = property(lambda self: (_ for _ in ()).throw(psutil.NoSuchProcess(100)))
        mock_iter.return_value = [proc]
        killer = ProcessKiller()
        # Should not crash
        assert killer.find_agent_processes() == []

    @patch("agentfirewall.process.psutil.process_iter")
    def test_custom_signatures(self, mock_iter):
        mock_iter.return_value = [_fake_proc(400, "my-custom-agent")]
        killer = ProcessKiller(signatures=["my-custom-agent"])
        found = killer.find_agent_processes()
        assert len(found) == 1


class TestKillAgents:
    @patch("agentfirewall.process.psutil.process_iter")
    def test_kill_returns_count(self, mock_iter):
        procs = [_fake_proc(100, "claude"), _fake_proc(200, "cursor")]
        mock_iter.return_value = procs
        killer = ProcessKiller()
        killed = killer.kill_agents()
        assert killed == 2
        for p in procs:
            p.send_signal.assert_called_once()

    @patch("agentfirewall.process.psutil.process_iter")
    def test_kill_handles_access_denied(self, mock_iter):
        proc = _fake_proc(100, "claude")
        proc.send_signal.side_effect = psutil.AccessDenied(100)
        mock_iter.return_value = [proc]
        killer = ProcessKiller()
        killed = killer.kill_agents()
        assert killed == 0

    @patch("agentfirewall.process.psutil.process_iter")
    def test_kill_handles_no_such_process(self, mock_iter):
        proc = _fake_proc(100, "claude")
        proc.send_signal.side_effect = psutil.NoSuchProcess(100)
        mock_iter.return_value = [proc]
        killer = ProcessKiller()
        killed = killer.kill_agents()
        assert killed == 0

    @patch("agentfirewall.process.psutil.process_iter")
    def test_kill_zero_when_none_found(self, mock_iter):
        mock_iter.return_value = []
        killer = ProcessKiller()
        assert killer.kill_agents() == 0
