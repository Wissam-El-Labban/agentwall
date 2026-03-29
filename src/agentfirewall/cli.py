"""CLI entrypoint for agentfirewall."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from pathlib import Path

PID_FILENAME = "watcher.pid"

import click

from agentfirewall.engine import Engine
from agentfirewall.schema import (
    ConfigError,
    CONFIG_FILENAME,
    DOTFILE_NAME,
    SUBDIRS,
    config_to_yaml,
    default_config,
    find_config,
    load_config,
)


def _load_engine() -> Engine | None:
    """Locate the nearest .agentfirewall/ directory and create an Engine, or None."""
    from agentfirewall.audit import AuditLogger

    config_path = find_config()
    if config_path is None:
        return None
    config = load_config(config_path)
    base_dir = config_path.parent
    audit = AuditLogger(config.logging, base_dir)
    return Engine(config, audit=audit)


@click.group()
@click.version_option(package_name="agentfirewall")
def main() -> None:
    """agentfirewall — protect your OS from destructive LLM agent tool calls."""


@main.command()
@click.option("--preset", type=click.Choice(["standard", "strict", "permissive"]), default="standard",
              help="Which built-in preset to use.")
@click.option("--force", is_flag=True, help="Overwrite existing .agentfirewall/ directory.")
def init(preset: str, force: bool) -> None:
    """Create a .agentfirewall/ directory with config in the current directory."""
    from agentfirewall.presets import get_preset

    target_dir = Path.cwd() / DOTFILE_NAME
    if target_dir.exists() and not force:
        click.echo(f"Error: {DOTFILE_NAME}/ already exists. Use --force to overwrite.", err=True)
        sys.exit(1)

    target_dir.mkdir(exist_ok=True)
    for subdir in SUBDIRS:
        (target_dir / subdir).mkdir(exist_ok=True)

    config = get_preset(preset)
    (target_dir / CONFIG_FILENAME).write_text(config_to_yaml(config), encoding="utf-8")
    click.echo(f"Created {DOTFILE_NAME}/ (preset: {preset})")


@main.command()
@click.argument("command_str")
def check(command_str: str) -> None:
    """Dry-run: check if a command would be allowed or blocked."""
    engine = _load_engine()
    if engine is None:
        click.echo(f"No {DOTFILE_NAME}/ found in current or parent directories.", err=True)
        sys.exit(2)

    result = engine.evaluate_command(command_str)
    symbol = {"allow": "✅", "deny": "🚫", "warn": "⚠️ "}[result.verdict.value]
    click.echo(f"{symbol}  {result.verdict.value.upper()}")
    click.echo(f"   Rule:   {result.rule}")
    click.echo(f"   Detail: {result.detail}")
    if result.blocked:
        sys.exit(1)


@main.command()
def status() -> None:
    """Show the current firewall status and loaded config."""
    config_path = find_config()
    if config_path is None:
        click.echo(f"No {DOTFILE_NAME}/ found in current or parent directories.")
        return

    try:
        config = load_config(config_path)
    except ConfigError as e:
        click.echo(f"Error loading config: {e}", err=True)
        sys.exit(1)

    click.echo(f"Config:    {config_path}")
    click.echo(f"Mode:      {config.mode.value}")
    click.echo(f"Sandbox:   root={config.sandbox.root!r}  escape={config.sandbox.allow_escape}")
    click.echo(f"Protected: {len(config.filesystem.protected_paths)} path patterns")
    click.echo(f"Blocklist: {len(config.commands.blocklist)} command patterns")
    if config.commands.allowlist:
        click.echo(f"Allowlist: {len(config.commands.allowlist)} command patterns (allowlist mode)")
    click.echo(f"Network:   {len(config.network.allowed_hosts)} allowed hosts, "
               f"{len(config.network.deny_egress_to)} denied targets")
    click.echo(f"Logging:   {'enabled' if config.logging.enabled else 'disabled'} → {config.logging.file}")

    # watcher status
    pid_file = config_path.parent / PID_FILENAME
    if pid_file.exists():
        try:
            pid = int(pid_file.read_text(encoding="utf-8").strip())
            os.kill(pid, 0)  # signal 0 = check if process exists
            click.echo(f"Watcher:   running (PID: {pid})")
        except (ProcessLookupError, ValueError):
            click.echo("Watcher:   not running (stale PID file)")
    else:
        click.echo("Watcher:   not running")

    # hooks status
    from agentfirewall.hooks.shell import detect_shell
    shell_name = detect_shell()
    rc_file = Path.home() / (f".{shell_name}rc")
    if rc_file.exists() and "agentfirewall" in rc_file.read_text(encoding="utf-8"):
        click.echo(f"Hooks:     installed ({shell_name})")
    else:
        click.echo("Hooks:     not installed")


@main.command()
@click.argument("path")
@click.option("--operation", "-o", type=click.Choice(["delete", "chmod", "write", "move_outside_sandbox"]),
              default="delete", help="Filesystem operation to simulate.")
def check_file(path: str, operation: str) -> None:
    """Dry-run: check if a file operation would be allowed or blocked."""
    from agentfirewall.schema import DenyOperation

    engine = _load_engine()
    if engine is None:
        click.echo(f"No {DOTFILE_NAME}/ found in current or parent directories.", err=True)
        sys.exit(1)

    op = DenyOperation(operation)
    result = engine.evaluate_file_operation(op, path)
    symbol = {"allow": "✅", "deny": "🚫", "warn": "⚠️ "}[result.verdict.value]
    click.echo(f"{symbol}  {result.verdict.value.upper()}")
    click.echo(f"   Rule:   {result.rule}")
    click.echo(f"   Detail: {result.detail}")
    if result.blocked:
        sys.exit(1)


@main.command()
@click.argument("host")
def check_network(host: str) -> None:
    """Dry-run: check if a network connection to HOST would be allowed."""
    engine = _load_engine()
    if engine is None:
        click.echo(f"No {DOTFILE_NAME}/ found in current or parent directories.", err=True)
        sys.exit(1)

    result = engine.evaluate_network(host)
    symbol = {"allow": "✅", "deny": "🚫", "warn": "⚠️ "}[result.verdict.value]
    click.echo(f"{symbol}  {result.verdict.value.upper()}")
    click.echo(f"   Rule:   {result.rule}")
    click.echo(f"   Detail: {result.detail}")

    if result.blocked:
        sys.exit(1)


@main.command()
def watch() -> None:
    """Start real-time filesystem monitoring (Ctrl+C to stop)."""
    from agentfirewall.audit import AuditLogger
    from agentfirewall.process import ProcessKiller
    from agentfirewall.watchers.filesystem import FirewallObserver

    config_path = find_config()
    if config_path is None:
        click.echo(f"No {DOTFILE_NAME}/ found in current or parent directories.", err=True)
        sys.exit(1)

    config = load_config(config_path)
    base_dir = config_path.parent
    audit = AuditLogger(config.logging, base_dir)
    engine = Engine(config, audit=audit)
    killer = ProcessKiller()

    watch_path = Path(config.sandbox.root or ".").resolve()
    click.echo(f"Watching {watch_path} ... Ctrl+C to stop")

    observer = FirewallObserver(engine, base_dir, process_killer=killer)
    observer.run_forever()


@main.command(name="install-hooks")
@click.option("--shell", type=click.Choice(["bash", "zsh"]), default=None,
              help="Target shell (auto-detected if omitted).")
def install_hooks(shell: str | None) -> None:
    """Install shell preexec hooks for command interception."""
    from agentfirewall.hooks.shell import install_hook

    rc = install_hook(shell)
    click.echo(f"Hooks installed in {rc}")


@main.command(name="uninstall-hooks")
@click.option("--shell", type=click.Choice(["bash", "zsh"]), default=None,
              help="Target shell (auto-detected if omitted).")
def uninstall_hooks(shell: str | None) -> None:
    """Remove shell preexec hooks."""
    from agentfirewall.hooks.shell import uninstall_hook

    removed = uninstall_hook(shell)
    click.echo("Hooks removed." if removed else "No hooks found.")


@main.command()
@click.argument("command", nargs=-1)
@click.option("--mountpoint", "-m", type=click.Path(), default=None,
              help="Custom mountpoint path (auto-generated if omitted).")
def sandbox(command: tuple[str, ...], mountpoint: str | None) -> None:
    """Mount a FUSE sandbox for true filesystem prevention.

    If COMMAND is provided, it runs inside the sandbox and the mount is
    automatically cleaned up on exit.  Without a command the sandbox stays
    mounted until you press Ctrl+C.
    """
    try:
        from agentfirewall.sandbox import mount as fuse_mount, run_sandboxed
    except RuntimeError as exc:
        click.echo(str(exc), err=True)
        sys.exit(1)

    from agentfirewall.audit import AuditLogger

    config_path = find_config()
    if config_path is None:
        click.echo(f"No {DOTFILE_NAME}/ found in current or parent directories.", err=True)
        sys.exit(1)

    config = load_config(config_path)
    base_dir = config_path.parent
    audit = AuditLogger(config.logging, base_dir)
    engine = Engine(config, audit=audit)

    source = Path(config.sandbox.root or ".").resolve()
    mp = Path(mountpoint) if mountpoint else None

    if command:
        click.echo(f"Sandbox: running {' '.join(command)}")
        exit_code = run_sandboxed(source, engine, list(command), audit=audit, mountpoint=mp)
        sys.exit(exit_code)
    else:
        from agentfirewall.sandbox import _default_mountpoint
        actual_mp = mp or _default_mountpoint(source)
        click.echo(f"Sandbox mounted at {actual_mp}")
        click.echo("Press Ctrl+C to unmount and exit.")
        try:
            fuse_mount(source, engine, audit=audit, mountpoint=mp, foreground=True)
        except KeyboardInterrupt:
            click.echo("\nUnmounting sandbox...")


@main.command()
@click.option("--preset", type=click.Choice(["standard", "strict", "permissive"]), default="standard",
              help="Which built-in preset to use.")
@click.option("--shell", type=click.Choice(["bash", "zsh"]), default=None,
              help="Target shell (auto-detected if omitted).")
@click.option("--force", is_flag=True, help="Overwrite existing .agentfirewall/ directory.")
@click.option("--sandbox", is_flag=True, help="Also start the FUSE sandbox.")
@click.option("--ui", is_flag=True, help="Also start the web UI dashboard.")
@click.option("--ui-port", default=5000, help="Port for the UI server (default: 5000).")
def protect(preset: str, shell: str | None, force: bool, sandbox: bool, ui: bool, ui_port: int) -> None:
    """One command to initialize, install hooks, and start the watcher."""
    from agentfirewall.hooks.shell import install_hook
    from agentfirewall.presets import get_preset

    # Step 1: init
    target_dir = Path.cwd() / DOTFILE_NAME
    if target_dir.exists() and not force:
        click.echo(f"Error: {DOTFILE_NAME}/ already exists. Use --force to reinitialize.", err=True)
        sys.exit(1)

    # Kill existing watcher before re-init (prevents orphan processes)
    if force:
        old_pid_file = target_dir / PID_FILENAME
        if old_pid_file.exists():
            try:
                old_pid = int(old_pid_file.read_text(encoding="utf-8").strip())
                os.kill(old_pid, signal.SIGTERM)
            except (ProcessLookupError, ValueError, OSError):
                pass
            old_pid_file.unlink(missing_ok=True)

    target_dir.mkdir(exist_ok=True)
    for subdir in SUBDIRS:
        (target_dir / subdir).mkdir(exist_ok=True)

    config = get_preset(preset)
    (target_dir / CONFIG_FILENAME).write_text(config_to_yaml(config), encoding="utf-8")
    click.echo(f"✅ Initialized {DOTFILE_NAME}/ (preset: {preset})")

    # Step 2: install shell hooks
    rc = install_hook(shell)
    click.echo(f"✅ Shell hooks installed → {rc}")

    # Step 3: start watcher in background
    pid_file = target_dir / PID_FILENAME
    proc = subprocess.Popen(
        [sys.executable, "-m", "agentfirewall.cli", "watch"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        cwd=str(Path.cwd()),
    )
    pid_file.write_text(str(proc.pid), encoding="utf-8")
    click.echo(f"✅ Watcher running in background (PID: {proc.pid})")

    # Step 4: start FUSE sandbox in background (optional)
    if sandbox:
        try:
            sandbox_proc = subprocess.Popen(
                [sys.executable, "-m", "agentfirewall.cli", "sandbox"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                cwd=str(Path.cwd()),
            )
            sandbox_pid_file = target_dir / "sandbox.pid"
            sandbox_pid_file.write_text(str(sandbox_proc.pid), encoding="utf-8")
            click.echo(f"✅ FUSE sandbox running in background (PID: {sandbox_proc.pid})")
        except Exception as e:
            click.echo(f"⚠️  FUSE sandbox failed to start: {e}")

    # Step 5: start UI in background (optional)
    if ui:
        try:
            from agentfirewall.ui.app import create_app  # noqa: F401
            ui_proc = subprocess.Popen(
                [sys.executable, "-m", "agentfirewall.cli", "ui", "--host", "0.0.0.0", "--port", str(ui_port), "--no-open"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                cwd=str(Path.cwd()),
            )
            ui_pid_file = target_dir / "ui.pid"
            ui_pid_file.write_text(str(ui_proc.pid), encoding="utf-8")
            click.echo(f"✅ UI dashboard running at http://localhost:{ui_port} (PID: {ui_proc.pid})")
        except ImportError:
            click.echo("⚠️  Flask not installed. Run: pip install flask")
        except Exception as e:
            click.echo(f"⚠️  UI failed to start: {e}")

    # Step 6: self-test
    from agentfirewall.audit import AuditLogger
    audit = AuditLogger(config.logging, target_dir)
    engine = Engine(config, audit=audit)
    test_result = engine.evaluate_command("rm -rf /")
    if test_result.blocked:
        click.echo('✅ Self-test: "rm -rf /" → DENY')
    else:
        click.echo('⚠️  Self-test: "rm -rf /" → not blocked (check your config)')

    click.echo("🛡  Protection active")

    # Step 7: source reminder
    from agentfirewall.hooks.shell import detect_shell
    shell_name = shell or detect_shell()
    rc_file = f"~/.{shell_name}rc"
    click.echo(f"\n⚠️  One more step — activate hooks in your current terminal:")
    click.echo(f"    source {rc_file}")


@main.command()
@click.option("--port", default=8741, help="Port to run the UI server on.")
@click.option("--host", default="127.0.0.1", help="Host to bind the UI server to.")
@click.option("--no-open", is_flag=True, help="Don't auto-open browser.")
def ui(port: int, host: str, no_open: bool) -> None:
    """Launch the web UI dashboard."""
    try:
        from agentfirewall.ui.app import create_app
    except ImportError:
        click.echo("Flask required. Install with: pip install agentfirewall[ui]", err=True)
        sys.exit(1)

    config_path = find_config()
    if config_path is None:
        click.echo(f"No {DOTFILE_NAME}/ found in current or parent directories.", err=True)
        sys.exit(1)

    app = create_app(config_dir=config_path.parent)
    url = f"http://{host}:{port}"
    click.echo(f"Starting agentfirewall UI at {url}")

    if not no_open:
        import webbrowser
        import threading
        threading.Timer(1.0, webbrowser.open, args=[url]).start()

    app.run(host=host, port=port, debug=False)


@main.command()
@click.option("--shell", type=click.Choice(["bash", "zsh"]), default=None,
              help="Target shell (auto-detected if omitted).")
@click.option("--remove-config", is_flag=True, help="Also remove the .agentfirewall/ directory.")
def unprotect(shell: str | None, remove_config: bool) -> None:
    """Stop the watcher, remove shell hooks, and disable protection."""
    import shutil
    from agentfirewall.hooks.shell import uninstall_hook

    target_dir = Path.cwd() / DOTFILE_NAME
    pid_file = target_dir / PID_FILENAME

    # Step 1: stop watcher
    if pid_file.exists():
        try:
            pid = int(pid_file.read_text(encoding="utf-8").strip())
            os.kill(pid, signal.SIGTERM)
            click.echo(f"✅ Watcher stopped (PID: {pid})")
        except (ProcessLookupError, ValueError):
            click.echo("⚠️  Watcher process not found (may have already stopped)")
        pid_file.unlink(missing_ok=True)
    else:
        click.echo("⚠️  No watcher PID file found")

    # Step 2: stop sandbox
    sandbox_pid_file = target_dir / "sandbox.pid"
    if sandbox_pid_file.exists():
        try:
            pid = int(sandbox_pid_file.read_text(encoding="utf-8").strip())
            os.kill(pid, signal.SIGTERM)
            click.echo(f"✅ Sandbox stopped (PID: {pid})")
        except (ProcessLookupError, ValueError):
            click.echo("⚠️  Sandbox process not found (may have already stopped)")
        sandbox_pid_file.unlink(missing_ok=True)

    # Step 3: stop UI
    ui_pid_file = target_dir / "ui.pid"
    if ui_pid_file.exists():
        try:
            pid = int(ui_pid_file.read_text(encoding="utf-8").strip())
            os.kill(pid, signal.SIGTERM)
            click.echo(f"✅ UI stopped (PID: {pid})")
        except (ProcessLookupError, ValueError):
            click.echo("⚠️  UI process not found (may have already stopped)")
        ui_pid_file.unlink(missing_ok=True)

    # Step 4: uninstall shell hooks
    removed = uninstall_hook(shell)
    click.echo("✅ Shell hooks removed." if removed else "⚠️  No shell hooks found.")

    # Step 5: optionally remove config
    if remove_config and target_dir.exists():
        shutil.rmtree(target_dir)
        click.echo(f"✅ Removed {DOTFILE_NAME}/")

    click.echo("🔓 Protection disabled")


if __name__ == "__main__":
    main()
