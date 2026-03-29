"""Flask app factory and API routes for the agentfirewall dashboard."""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict
from pathlib import Path
from typing import Generator

from flask import Flask, Response, jsonify, render_template, request

from agentfirewall.engine import Engine
from agentfirewall.schema import (
    ConfigError,
    DenyOperation,
    FirewallConfig,
    FirewallMode,
    config_to_yaml,
    find_config,
    load_config,
)


def create_app(config_dir: Path | None = None) -> Flask:
    """Create and configure the Flask application.

    Args:
        config_dir: Path to the .agentfirewall/ directory. If None,
                    uses find_config() to locate it.
    """
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
    )
    app.secret_key = os.urandom(32)

    if config_dir is not None:
        app.config["AGENTFIREWALL_DIR"] = Path(config_dir)
    else:
        config_path = find_config()
        if config_path is None:
            raise ConfigError("No .agentfirewall/ directory found.")
        app.config["AGENTFIREWALL_DIR"] = config_path.parent

    def _config_path() -> Path:
        return app.config["AGENTFIREWALL_DIR"] / "config.yaml"

    def _load() -> FirewallConfig:
        return load_config(_config_path())

    def _save(config: FirewallConfig) -> None:
        _config_path().write_text(config_to_yaml(config), encoding="utf-8")

    def _log_path() -> Path:
        config = _load()
        return app.config["AGENTFIREWALL_DIR"] / config.logging.file

    # ── Page routes ─────────────────────────────────────────

    @app.route("/")
    def dashboard():
        config = _load()
        stats = {
            "blocklist_count": len(config.commands.blocklist),
            "protected_paths_count": len(config.filesystem.protected_paths),
            "deny_operations": [op.value for op in config.filesystem.deny_operations],
        }
        return render_template("dashboard.html", config=config, stats=stats)

    @app.route("/config")
    def config_page():
        config = _load()
        return render_template("config.html", config=config)

    @app.route("/logs")
    def logs_page():
        return render_template("logs.html")

    # ── API routes ──────────────────────────────────────────

    @app.route("/api/config", methods=["GET"])
    def api_get_config():
        config = _load()
        return jsonify(_config_to_dict(config))

    @app.route("/api/config", methods=["PUT"])
    def api_put_config():
        data = request.get_json()
        if data is None:
            return jsonify({"error": "Request body must be JSON"}), 400

        config = _load()
        _apply_config_changes(config, data)
        _save(config)
        return jsonify(_config_to_dict(config))

    @app.route("/api/preset", methods=["POST"])
    def api_preset():
        from agentfirewall.presets import get_preset

        data = request.get_json()
        if data is None or "preset" not in data:
            return jsonify({"error": "Request body must include 'preset'"}), 400

        preset_name = data["preset"]
        try:
            config = get_preset(preset_name)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        _save(config)
        return jsonify(_config_to_dict(config))

    @app.route("/api/logs", methods=["GET"])
    def api_logs():
        verdict_filter = request.args.get("verdict")
        search_query = request.args.get("q", "").lower()
        limit = min(int(request.args.get("limit", 500)), 5000)

        log_file = _log_path()
        entries: list[dict] = []
        if log_file.is_file():
            lines = log_file.read_text(encoding="utf-8").strip().splitlines()
            for line in reversed(lines):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if verdict_filter and entry.get("verdict") != verdict_filter:
                    continue
                if search_query and search_query not in json.dumps(entry).lower():
                    continue
                entries.append(entry)
                if len(entries) >= limit:
                    break

        return jsonify({"entries": entries, "total": len(entries)})

    @app.route("/api/logs/stream")
    def api_logs_stream():
        log_file = _log_path()
        return Response(_sse_generator(log_file), mimetype="text/event-stream")

    @app.route("/api/agents", methods=["GET"])
    def api_agents():
        # Stubbed — Phase 3 (Agent Discovery) not yet implemented.
        # Wire to discover_all() when Phase 3 lands.
        return jsonify({"agents": [], "discovery_available": False})

    return app


def _sse_generator(log_file: Path) -> Generator[str, None, None]:
    """Tail a log file and yield lines as SSE events."""
    try:
        if log_file.is_file():
            fh = open(log_file, "r", encoding="utf-8")
            fh.seek(0, 2)  # seek to end
        else:
            fh = None

        while True:
            if fh is None:
                if log_file.is_file():
                    fh = open(log_file, "r", encoding="utf-8")
                    fh.seek(0, 2)
                else:
                    time.sleep(0.2)
                    yield ": keepalive\n\n"
                    continue

            line = fh.readline()
            if line:
                line = line.strip()
                if line:
                    yield f"data: {line}\n\n"
            else:
                # Check for log rotation (file replaced)
                try:
                    if not log_file.is_file() or log_file.stat().st_ino != os.fstat(fh.fileno()).st_ino:
                        fh.close()
                        fh = None
                        continue
                except OSError:
                    fh.close()
                    fh = None
                    continue
                time.sleep(0.2)
                yield ": keepalive\n\n"
    except GeneratorExit:
        if fh is not None:
            fh.close()


def _config_to_dict(config: FirewallConfig) -> dict:
    """Convert FirewallConfig to a JSON-serializable dict."""
    return {
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


def _apply_config_changes(config: FirewallConfig, data: dict) -> None:
    """Apply partial config changes from a JSON dict to a FirewallConfig."""
    if "mode" in data:
        config.mode = FirewallMode(data["mode"])

    if "sandbox" in data:
        sb = data["sandbox"]
        if "root" in sb:
            config.sandbox.root = sb["root"]
        if "allow_escape" in sb:
            config.sandbox.allow_escape = bool(sb["allow_escape"])

    if "filesystem" in data:
        fs = data["filesystem"]
        if "protected_paths" in fs:
            config.filesystem.protected_paths = list(fs["protected_paths"])
        if "deny_operations" in fs:
            config.filesystem.deny_operations = [DenyOperation(op) for op in fs["deny_operations"]]

    if "commands" in data:
        cmds = data["commands"]
        if "blocklist" in cmds:
            config.commands.blocklist = list(cmds["blocklist"])
        if "allowlist" in cmds:
            config.commands.allowlist = list(cmds["allowlist"])

    if "network" in data:
        net = data["network"]
        if "allowed_hosts" in net:
            config.network.allowed_hosts = list(net["allowed_hosts"])
        if "deny_egress_to" in net:
            config.network.deny_egress_to = list(net["deny_egress_to"])
        if "max_upload_bytes" in net:
            config.network.max_upload_bytes = int(net["max_upload_bytes"])

    if "logging" in data:
        log = data["logging"]
        if "enabled" in log:
            config.logging.enabled = bool(log["enabled"])
        if "file" in log:
            config.logging.file = log["file"]
        if "level" in log:
            config.logging.level = log["level"]
