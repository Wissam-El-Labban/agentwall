"""Schema definition and validation for .agentfirewall config files."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml


class FirewallMode(Enum):
    ENFORCE = "enforce"
    AUDIT = "audit"
    OFF = "off"


class DenyOperation(Enum):
    DELETE = "delete"
    CHMOD = "chmod"
    MOVE_OUTSIDE_SANDBOX = "move_outside_sandbox"
    WRITE = "write"


@dataclass
class SandboxConfig:
    root: str = "."
    allow_escape: bool = False


@dataclass
class FilesystemConfig:
    protected_paths: list[str] = field(default_factory=lambda: [
        ".agentfirewall/**",
        ".git/**",
        ".env",
        ".ssh/**",
    ])
    deny_operations: list[DenyOperation] = field(default_factory=lambda: [
        DenyOperation.DELETE,
        DenyOperation.MOVE_OUTSIDE_SANDBOX,
    ])


@dataclass
class CommandsConfig:
    blocklist: list[str] = field(default_factory=list)
    allowlist: list[str] = field(default_factory=list)


@dataclass
class NetworkConfig:
    allowed_hosts: list[str] = field(default_factory=list)
    deny_egress_to: list[str] = field(default_factory=lambda: [
        "169.254.169.254",
        "metadata.google.internal",
    ])
    max_upload_bytes: int = 10_485_760  # 10 MB


@dataclass
class LoggingConfig:
    enabled: bool = True
    file: str = "logs/firewall.log"
    level: str = "warn"


@dataclass
class FirewallConfig:
    version: int = 1
    mode: FirewallMode = FirewallMode.ENFORCE
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    filesystem: FilesystemConfig = field(default_factory=FilesystemConfig)
    commands: CommandsConfig = field(default_factory=CommandsConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)


DOTFILE_NAME = ".agentfirewall"
CONFIG_FILENAME = "config.yaml"
SUBDIRS = ["rules", "logs", "hooks", "plugins"]


class ConfigError(Exception):
    """Raised when the .agentfirewall config is invalid."""


def find_config(start_dir: str | Path | None = None) -> Path | None:
    """Walk up from start_dir looking for a .agentfirewall/ directory.

    Returns the path to config.yaml inside the first .agentfirewall/ found,
    or None if no such directory exists.
    """
    current = Path(start_dir or os.getcwd()).resolve()
    for directory in [current, *current.parents]:
        candidate = directory / DOTFILE_NAME
        if candidate.is_dir():
            config_file = candidate / CONFIG_FILENAME
            if config_file.is_file():
                return config_file
    return None


def _parse_sandbox(raw: dict[str, Any]) -> SandboxConfig:
    return SandboxConfig(
        root=str(raw.get("root", ".")),
        allow_escape=bool(raw.get("allow_escape", False)),
    )


def _parse_filesystem(raw: dict[str, Any]) -> FilesystemConfig:
    ops = []
    for op in raw.get("deny_operations", ["delete", "move_outside_sandbox"]):
        try:
            ops.append(DenyOperation(op))
        except ValueError:
            raise ConfigError(f"Unknown deny_operation: {op!r}")
    return FilesystemConfig(
        protected_paths=list(raw.get("protected_paths", FilesystemConfig().protected_paths)),
        deny_operations=ops,
    )


def _parse_commands(raw: dict[str, Any]) -> CommandsConfig:
    return CommandsConfig(
        blocklist=list(raw.get("blocklist", [])),
        allowlist=list(raw.get("allowlist", [])),
    )


def _parse_network(raw: dict[str, Any]) -> NetworkConfig:
    return NetworkConfig(
        allowed_hosts=list(raw.get("allowed_hosts", [])),
        deny_egress_to=list(raw.get("deny_egress_to", NetworkConfig().deny_egress_to)),
        max_upload_bytes=int(raw.get("max_upload_bytes", 10_485_760)),
    )


def _parse_logging(raw: dict[str, Any]) -> LoggingConfig:
    return LoggingConfig(
        enabled=bool(raw.get("enabled", True)),
        file=str(raw.get("file", "logs/firewall.log")),
        level=str(raw.get("level", "warn")),
    )


def _parse_mode(raw: str) -> FirewallMode:
    try:
        return FirewallMode(raw)
    except ValueError:
        raise ConfigError(f"Unknown mode: {raw!r}. Must be one of: enforce, audit, off")


def load_config(path: str | Path) -> FirewallConfig:
    """Load and validate a .agentfirewall YAML file."""
    path = Path(path)
    if not path.is_file():
        raise ConfigError(f"Config file not found: {path}")

    text = path.read_text(encoding="utf-8")
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ConfigError(f"Invalid YAML in {path}: {e}") from e

    if not isinstance(raw, dict):
        raise ConfigError(f"Config must be a YAML mapping, got {type(raw).__name__}")

    version = raw.get("version", 1)
    if version != 1:
        raise ConfigError(f"Unsupported config version: {version}. Only version 1 is supported.")

    return FirewallConfig(
        version=version,
        mode=_parse_mode(raw.get("mode", "enforce")),
        sandbox=_parse_sandbox(raw.get("sandbox", {})),
        filesystem=_parse_filesystem(raw.get("filesystem", {})),
        commands=_parse_commands(raw.get("commands", {})),
        network=_parse_network(raw.get("network", {})),
        logging=_parse_logging(raw.get("logging", {})),
    )


def default_config() -> FirewallConfig:
    """Return the default FirewallConfig (used by `agentfirewall init`)."""
    return FirewallConfig(
        commands=CommandsConfig(
            blocklist=[
                "rm -rf /",
                "rm -rf ~",
                "rm -rf /*",
                "dd if=*of=/dev/*",
                "mkfs.*",
                ":(){ :|:& };:",
                "chmod -R 777",
                "sudo rm*",
                "git push --force",
                "git push.*--force",
                "git reset --hard",
                "git clean -fd",
                "kill -9",
                "pkill",
                "> /dev/sda",
            ],
        ),
        network=NetworkConfig(
            allowed_hosts=[
                "github.com",
                "api.openai.com",
                "api.anthropic.com",
            ],
        ),
    )


def config_to_yaml(config: FirewallConfig) -> str:
    """Serialize a FirewallConfig back to YAML text."""
    data: dict[str, Any] = {
        "version": config.version,
        "mode": config.mode.value,
        "sandbox": {
            "root": config.sandbox.root,
            "allow_escape": config.sandbox.allow_escape,
        },
        "filesystem": {
            "protected_paths": config.filesystem.protected_paths,
            "deny_operations": [op.value for op in config.filesystem.deny_operations],
        },
        "commands": {
            "blocklist": config.commands.blocklist,
            "allowlist": config.commands.allowlist,
        },
        "network": {
            "allowed_hosts": config.network.allowed_hosts,
            "deny_egress_to": config.network.deny_egress_to,
            "max_upload_bytes": config.network.max_upload_bytes,
        },
        "logging": {
            "enabled": config.logging.enabled,
            "file": config.logging.file,
            "level": config.logging.level,
        },
    }
    return yaml.dump(data, default_flow_style=False, sort_keys=False)
