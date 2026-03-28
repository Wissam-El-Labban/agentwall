"""Rule evaluation engine — decides allow / deny / warn for each action."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from agentfirewall.schema import (
    DenyOperation,
    FirewallConfig,
    FirewallMode,
)

if TYPE_CHECKING:
    from agentfirewall.audit import AuditLogger


class Verdict(Enum):
    ALLOW = "allow"
    DENY = "deny"
    WARN = "warn"


@dataclass
class RuleResult:
    verdict: Verdict
    rule: str          # which rule triggered
    detail: str        # human-readable explanation

    @property
    def blocked(self) -> bool:
        return self.verdict == Verdict.DENY


class Engine:
    """Evaluates actions against a loaded FirewallConfig."""

    def __init__(self, config: FirewallConfig, audit: AuditLogger | None = None) -> None:
        self.config = config
        self._audit = audit
        self._blocklist_patterns = [
            self._compile_command_pattern(p) for p in config.commands.blocklist
        ]
        self._allowlist_patterns = [
            self._compile_command_pattern(p) for p in config.commands.allowlist
        ]
        self._sandbox_root: Path | None = None
        if config.sandbox.root:
            self._sandbox_root = Path(config.sandbox.root).resolve()

    # ── public API ──────────────────────────────────────────────

    def evaluate_command(self, command: str) -> RuleResult:
        """Evaluate a shell command string against all rules."""
        if self.config.mode == FirewallMode.OFF:
            return RuleResult(Verdict.ALLOW, "mode=off", "Firewall is disabled")

        # 1. Allowlist check (if non-empty, only allow matching commands)
        if self._allowlist_patterns:
            if not self._matches_any(command, self._allowlist_patterns):
                result = self._make_result(
                    Verdict.DENY,
                    "commands.allowlist",
                    f"Command not in allowlist: {command!r}",
                )
                self._log("command", command, result)
                return result

        # 2. Blocklist check
        for i, pattern in enumerate(self._blocklist_patterns):
            if pattern.search(command):
                result = self._make_result(
                    Verdict.DENY,
                    f"commands.blocklist[{i}]",
                    f"Command matches blocklist pattern {self.config.commands.blocklist[i]!r}",
                )
                self._log("command", command, result)
                return result

        result = RuleResult(Verdict.ALLOW, "default", "No rules matched")
        self._log("command", command, result)
        return result

    def evaluate_file_operation(
        self,
        operation: DenyOperation,
        path: str | Path,
    ) -> RuleResult:
        """Evaluate a filesystem operation on a given path."""
        if self.config.mode == FirewallMode.OFF:
            return RuleResult(Verdict.ALLOW, "mode=off", "Firewall is disabled")

        path = Path(path)

        # Check sandbox boundary
        if not self.config.sandbox.allow_escape and self._sandbox_root:
            try:
                resolved = (self._sandbox_root / path).resolve() if not path.is_absolute() else path.resolve()
                resolved.relative_to(self._sandbox_root)
            except ValueError:
                result = self._make_result(
                    Verdict.DENY,
                    "sandbox.allow_escape=false",
                    f"Operation escapes sandbox root {self._sandbox_root}: {path}",
                )
                self._log("file", str(path), result)
                return result

        # Check protected paths
        if operation in self.config.filesystem.deny_operations:
            for pattern in self.config.filesystem.protected_paths:
                if self._path_matches(path, pattern):
                    result = self._make_result(
                        Verdict.DENY,
                        f"filesystem.protected_paths:{pattern}",
                        f"Operation {operation.value!r} denied on protected path: {path}",
                    )
                    self._log("file", str(path), result)
                    return result

        result = RuleResult(Verdict.ALLOW, "default", "No rules matched")
        self._log("file", str(path), result)
        return result

    def evaluate_network(self, host: str) -> RuleResult:
        """Evaluate an outbound network connection to a host."""
        if self.config.mode == FirewallMode.OFF:
            return RuleResult(Verdict.ALLOW, "mode=off", "Firewall is disabled")

        # Check deny list first
        for denied in self.config.network.deny_egress_to:
            if host == denied or fnmatch.fnmatch(host, denied):
                result = self._make_result(
                    Verdict.DENY,
                    f"network.deny_egress_to:{denied}",
                    f"Outbound connection to {host!r} is blocked",
                )
                self._log("network", host, result)
                return result

        # If allowed_hosts is set, only those hosts are permitted
        if self.config.network.allowed_hosts:
            for allowed in self.config.network.allowed_hosts:
                if host == allowed or fnmatch.fnmatch(host, allowed):
                    result = RuleResult(Verdict.ALLOW, f"network.allowed_hosts:{allowed}", "Host is allowed")
                    self._log("network", host, result)
                    return result
            result = self._make_result(
                Verdict.DENY,
                "network.allowed_hosts",
                f"Host {host!r} not in allowed hosts list",
            )
            self._log("network", host, result)
            return result

        result = RuleResult(Verdict.ALLOW, "default", "No rules matched")
        self._log("network", host, result)
        return result

    # ── internal helpers ────────────────────────────────────────

    def _make_result(self, verdict: Verdict, rule: str, detail: str) -> RuleResult:
        """In audit mode, downgrade DENY → WARN."""
        if self.config.mode == FirewallMode.AUDIT and verdict == Verdict.DENY:
            return RuleResult(Verdict.WARN, rule, f"[AUDIT] {detail}")
        return RuleResult(verdict, rule, detail)

    def _log(self, action_type: str, target: str, result: RuleResult) -> None:
        if self._audit is not None:
            self._audit.log_decision(action_type, target, result)

    @staticmethod
    def _compile_command_pattern(pattern: str) -> re.Pattern[str]:
        """Convert a blocklist/allowlist glob-style pattern to a regex.

        Supports shell-style wildcards: * matches anything.
        The pattern is matched anywhere in the command string.
        """
        # Escape everything except *, then convert * to .*
        escaped = re.escape(pattern).replace(r"\*", ".*")
        return re.compile(escaped, re.IGNORECASE)

    @staticmethod
    def _matches_any(command: str, patterns: list[re.Pattern[str]]) -> bool:
        return any(p.search(command) for p in patterns)

    @staticmethod
    def _path_matches(path: Path, pattern: str) -> bool:
        """Check if a path matches a glob-style pattern.

        Supports relative matching against the path's parts and ** globs.
        """
        path_str = str(PurePosixPath(path))
        # Try matching against the full path and just the filename
        return fnmatch.fnmatch(path_str, pattern) or fnmatch.fnmatch(path.name, pattern)
