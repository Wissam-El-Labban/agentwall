"""LLM agent process identification and termination."""

from __future__ import annotations

import logging
import os
import signal

import psutil

logger = logging.getLogger(__name__)

AGENT_SIGNATURES: list[str] = [
    "claude",
    "cursor",
    "copilot-agent",
    "windsurf",
    "aider",
]

# Separate list — these match many non-agent processes, only check cmdline
_BROAD_SIGNATURES: list[str] = [
    "node",
    "code",
]

_SAFE_PIDS = frozenset({0, 1})


class ProcessKiller:
    """Finds and terminates known LLM agent processes."""

    def __init__(self, signatures: list[str] | None = None) -> None:
        self._signatures = signatures or AGENT_SIGNATURES
        self._my_pid = os.getpid()
        self._my_ppid = os.getppid()

    def find_agent_processes(self) -> list[psutil.Process]:
        """Return running processes that match known agent signatures."""
        matches: list[psutil.Process] = []
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                pid = proc.info["pid"]
                if pid in _SAFE_PIDS or pid == self._my_pid or pid == self._my_ppid:
                    continue

                name = (proc.info["name"] or "").lower()
                cmdline = proc.info["cmdline"] or []
                cmdline_str = " ".join(cmdline).lower()

                # Exact signatures — match process name
                if any(sig in name for sig in self._signatures):
                    matches.append(proc)
                    continue

                # Broad signatures — only match if cmdline contains agent-related tokens
                if any(sig in name for sig in _BROAD_SIGNATURES):
                    if any(agent in cmdline_str for agent in self._signatures):
                        matches.append(proc)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return matches

    def kill_agents(self) -> int:
        """Find and terminate agent processes. Returns count of killed processes."""
        killed = 0
        for proc in self.find_agent_processes():
            try:
                proc.send_signal(signal.SIGTERM)
                logger.warning("Killed agent process: pid=%d name=%s", proc.pid, proc.name())
                killed += 1
            except psutil.NoSuchProcess:
                pass
            except psutil.AccessDenied:
                logger.warning("Access denied killing pid=%d", proc.pid)
        return killed
