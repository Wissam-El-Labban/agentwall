"""Built-in firewall presets."""

from __future__ import annotations

from agentfirewall.schema import (
    CommandsConfig,
    DenyOperation,
    FilesystemConfig,
    FirewallConfig,
    FirewallMode,
    LoggingConfig,
    NetworkConfig,
    SandboxConfig,
)

# ── Shared dangerous command patterns ─────────────────────────

_COMMON_BLOCKLIST = [
    "rm -rf /",
    "rm -rf ~",
    "rm -rf /*",
    "dd if=*of=/dev/*",
    "mkfs.*",
    ":(){ :|:& };:",
    "chmod -R 777",
    "sudo rm*",
    "git push --force",
    "git push*--force",
    "git reset --hard",
    "git clean -fd",
    "> /dev/sda",
]

_EXTRA_STRICT_BLOCKLIST = [
    "kill*",
    "pkill*",
    "sudo *",
    "curl*|*sh",
    "wget*|*sh",
    "eval *",
    "exec *",
    "python*-c*os.*",
    "nc *",
    "ncat *",
]


def _standard() -> FirewallConfig:
    """Standard preset: blocks known-destructive commands, protects common sensitive paths."""
    return FirewallConfig(
        mode=FirewallMode.ENFORCE,
        sandbox=SandboxConfig(root=".", allow_escape=False),
        filesystem=FilesystemConfig(
            protected_paths=[".agentfirewall/**", ".git/**", ".env", ".ssh/**", "/etc/**"],
            deny_operations=[DenyOperation.DELETE, DenyOperation.MOVE_OUTSIDE_SANDBOX],
        ),
        commands=CommandsConfig(blocklist=list(_COMMON_BLOCKLIST)),
        network=NetworkConfig(
            allowed_hosts=["github.com", "api.openai.com", "api.anthropic.com"],
            deny_egress_to=["169.254.169.254", "metadata.google.internal"],
        ),
        logging=LoggingConfig(enabled=True, file="logs/firewall.log", level="warn"),
    )


def _strict() -> FirewallConfig:
    """Strict preset: deny-by-default, expanded blocklist, no sandbox escape."""
    config = _standard()
    config.commands.blocklist = list(_COMMON_BLOCKLIST) + list(_EXTRA_STRICT_BLOCKLIST)
    config.filesystem.deny_operations = list(DenyOperation)
    config.logging.level = "info"
    config.logging.log_all_activity = True
    return config


def _permissive() -> FirewallConfig:
    """Permissive preset: audit mode only (warn, never block)."""
    config = _standard()
    config.mode = FirewallMode.AUDIT
    config.sandbox.allow_escape = True
    config.logging.level = "info"
    return config


_PRESETS: dict[str, callable] = {
    "standard": _standard,
    "strict": _strict,
    "permissive": _permissive,
}


def get_preset(name: str) -> FirewallConfig:
    """Return a FirewallConfig for the named preset."""
    factory = _PRESETS.get(name)
    if factory is None:
        available = ", ".join(_PRESETS)
        raise ValueError(f"Unknown preset {name!r}. Available: {available}")
    return factory()


def list_presets() -> list[str]:
    """Return the names of available presets."""
    return list(_PRESETS.keys())
