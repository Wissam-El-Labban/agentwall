"""Cross-platform filesystem watcher using watchdog."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

import click
from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

from agentfirewall.engine import Engine, Verdict
from agentfirewall.schema import DenyOperation

if TYPE_CHECKING:
    from watchdog.events import FileSystemEvent

    from agentfirewall.process import ProcessKiller

# Map watchdog event types to DenyOperation
_EVENT_TO_OP = {
    FileCreatedEvent: DenyOperation.CREATE,
    FileDeletedEvent: DenyOperation.DELETE,
    FileModifiedEvent: DenyOperation.WRITE,
    FileMovedEvent: DenyOperation.MOVE_OUTSIDE_SANDBOX,
}


class FirewallHandler(FileSystemEventHandler):
    """Evaluates watchdog filesystem events against the firewall engine."""

    def __init__(
        self,
        engine: Engine,
        base_dir: Path,
        process_killer: ProcessKiller | None = None,
    ) -> None:
        super().__init__()
        self._engine = engine
        self._base_dir = str(base_dir.resolve())
        self._killer = process_killer
        self._watch_root = Path(engine.config.sandbox.root or ".").resolve()
        self._audit = engine._audit

    def on_created(self, event: FileSystemEvent) -> None:
        self._handle(event)

    def on_deleted(self, event: FileSystemEvent) -> None:
        self._handle(event)

    def on_modified(self, event: FileSystemEvent) -> None:
        self._handle(event)

    def on_moved(self, event: FileSystemEvent) -> None:
        self._handle(event)

    def _handle(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return

        src = event.src_path
        if src.startswith(self._base_dir):
            return

        operation = _EVENT_TO_OP.get(type(event))
        if operation is None:
            return

        # For moved events, evaluate the destination path
        if isinstance(event, FileMovedEvent):
            path = event.dest_path
        else:
            path = src

        # Convert to relative path so engine patterns (.git/**) match
        try:
            rel_path = str(Path(path).relative_to(self._watch_root))
        except ValueError:
            rel_path = path

        result = self._engine.evaluate_file_operation(operation, rel_path)

        # Log all observed activity when log_all_activity is enabled
        if result.verdict == Verdict.ALLOW and self._audit is not None:
            self._audit.log_activity(operation.value, rel_path)

        if result.verdict in (Verdict.DENY, Verdict.WARN):
            symbol = "🚫" if result.verdict == Verdict.DENY else "⚠️ "
            click.echo(
                f"{symbol}  [{result.verdict.value.upper()}] {operation.value} on {path}\n"
                f"   Rule:   {result.rule}\n"
                f"   Detail: {result.detail}",
                err=True,
            )
            if result.verdict == Verdict.DENY and self._killer is not None:
                killed = self._killer.kill_agents()
                if killed:
                    click.echo(f"   Killed {killed} agent process(es)", err=True)


class FirewallObserver:
    """Wraps watchdog Observer with firewall-aware lifecycle."""

    def __init__(
        self,
        engine: Engine,
        base_dir: Path,
        process_killer: ProcessKiller | None = None,
    ) -> None:
        self._engine = engine
        self._base_dir = base_dir
        self._killer = process_killer
        self._observer: Observer | None = None

    def start(self) -> None:
        handler = FirewallHandler(self._engine, self._base_dir, self._killer)
        watch_path = self._engine.config.sandbox.root or "."
        watch_path = str(Path(watch_path).resolve())

        self._observer = Observer()
        self._observer.schedule(handler, watch_path, recursive=True)
        self._observer.start()

    def stop(self) -> None:
        if self._observer is not None:
            self._observer.stop()
            self._observer.join()
            self._observer = None

    def run_forever(self) -> None:
        """Start watching and block until Ctrl+C."""
        self.start()
        try:
            self._observer.join()
        except KeyboardInterrupt:
            click.echo("\nStopping watcher...")
        finally:
            self.stop()
