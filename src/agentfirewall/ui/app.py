"""Flask app factory and API routes for the agentfirewall dashboard."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Generator

from flask import Flask, Response, jsonify, render_template, request

from agentfirewall.engine import Engine
from agentfirewall.schema import (
    CONFIG_FILENAME,
    ConfigError,
    DenyOperation,
    DOTFILE_NAME,
    FirewallConfig,
    FirewallMode,
    config_to_yaml,
    find_config,
    load_config,
)

PID_FILENAME = "watcher.pid"


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

    @app.route("/analytics")
    def analytics_page():
        return render_template("analytics.html")

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
        from agentfirewall.process import ProcessKiller

        try:
            killer = ProcessKiller()
            procs = killer.find_agent_processes()
            agents = []
            for proc in procs:
                try:
                    agents.append({
                        "pid": proc.pid,
                        "name": proc.name(),
                        "cmdline": " ".join(proc.cmdline()[:6]),
                    })
                except Exception:
                    continue
            return jsonify({"agents": agents, "discovery_available": True})
        except Exception:
            return jsonify({"agents": [], "discovery_available": True})

    @app.route("/api/status", methods=["GET"])
    def api_status():
        af_dir = app.config["AGENTFIREWALL_DIR"]
        config = _load()

        # Watcher status
        watcher_status = {"running": False, "pid": None}
        pid_file = af_dir / PID_FILENAME
        if pid_file.exists():
            try:
                pid = int(pid_file.read_text(encoding="utf-8").strip())
                os.kill(pid, 0)
                watcher_status = {"running": True, "pid": pid}
            except (ProcessLookupError, ValueError, OSError):
                watcher_status = {"running": False, "pid": None}

        # Sandbox status
        sandbox_status = {"running": False, "pid": None}
        sandbox_pid_file = af_dir / "sandbox.pid"
        if sandbox_pid_file.exists():
            try:
                pid = int(sandbox_pid_file.read_text(encoding="utf-8").strip())
                os.kill(pid, 0)
                sandbox_status = {"running": True, "pid": pid}
            except (ProcessLookupError, ValueError, OSError):
                sandbox_status = {"running": False, "pid": None}

        # Hooks status
        from agentfirewall.hooks.shell import detect_shell, GUARD_BEGIN
        shell_name = detect_shell()
        rc_file = Path.home() / f".{shell_name}rc"
        hooks_installed = False
        if rc_file.exists():
            hooks_installed = GUARD_BEGIN in rc_file.read_text(encoding="utf-8")

        return jsonify({
            "config_path": str(af_dir),
            "mode": config.mode.value,
            "watcher": watcher_status,
            "sandbox": sandbox_status,
            "hooks": {"installed": hooks_installed, "shell": shell_name, "rc_file": str(rc_file)},
        })

    @app.route("/api/check/command", methods=["POST"])
    def api_check_command():
        data = request.get_json()
        if data is None or "command" not in data:
            return jsonify({"error": "Request body must include 'command'"}), 400

        config = _load()
        engine = Engine(config)
        result = engine.evaluate_command(data["command"])
        return jsonify({
            "verdict": result.verdict.value,
            "rule": result.rule,
            "detail": result.detail,
            "blocked": result.blocked,
        })

    @app.route("/api/check/file", methods=["POST"])
    def api_check_file():
        data = request.get_json()
        if data is None or "path" not in data or "operation" not in data:
            return jsonify({"error": "Request body must include 'path' and 'operation'"}), 400

        try:
            op = DenyOperation(data["operation"])
        except ValueError:
            return jsonify({"error": f"Invalid operation: {data['operation']}"}), 400

        config = _load()
        engine = Engine(config)
        result = engine.evaluate_file_operation(op, data["path"])
        return jsonify({
            "verdict": result.verdict.value,
            "rule": result.rule,
            "detail": result.detail,
            "blocked": result.blocked,
        })

    @app.route("/api/check/network", methods=["POST"])
    def api_check_network():
        data = request.get_json()
        if data is None or "host" not in data:
            return jsonify({"error": "Request body must include 'host'"}), 400

        config = _load()
        engine = Engine(config)
        result = engine.evaluate_network(data["host"])
        return jsonify({
            "verdict": result.verdict.value,
            "rule": result.rule,
            "detail": result.detail,
            "blocked": result.blocked,
        })

    @app.route("/api/watcher", methods=["POST"])
    def api_watcher():
        data = request.get_json()
        if data is None or "action" not in data:
            return jsonify({"error": "Request body must include 'action'"}), 400

        af_dir = app.config["AGENTFIREWALL_DIR"]
        pid_file = af_dir / PID_FILENAME
        action = data["action"]

        if action == "start":
            # Check if already running
            if pid_file.exists():
                try:
                    pid = int(pid_file.read_text(encoding="utf-8").strip())
                    os.kill(pid, 0)
                    return jsonify({"status": "already_running", "pid": pid})
                except (ProcessLookupError, ValueError, OSError):
                    pid_file.unlink(missing_ok=True)

            proc = subprocess.Popen(
                [sys.executable, "-m", "agentfirewall.cli", "watch"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                cwd=str(af_dir.parent),
            )
            pid_file.write_text(str(proc.pid), encoding="utf-8")
            return jsonify({"status": "started", "pid": proc.pid})

        elif action == "stop":
            if not pid_file.exists():
                return jsonify({"status": "not_running"})
            try:
                pid = int(pid_file.read_text(encoding="utf-8").strip())
                os.kill(pid, signal.SIGTERM)
                pid_file.unlink(missing_ok=True)
                return jsonify({"status": "stopped", "pid": pid})
            except (ProcessLookupError, ValueError, OSError):
                pid_file.unlink(missing_ok=True)
                return jsonify({"status": "not_running"})

        return jsonify({"error": "action must be 'start' or 'stop'"}), 400

    @app.route("/api/hooks", methods=["POST"])
    def api_hooks():
        from agentfirewall.hooks.shell import install_hook, uninstall_hook

        data = request.get_json()
        if data is None or "action" not in data:
            return jsonify({"error": "Request body must include 'action'"}), 400

        shell = data.get("shell")
        action = data["action"]

        if action == "install":
            rc = install_hook(shell)
            return jsonify({"installed": True, "rc_file": str(rc)})
        elif action == "uninstall":
            removed = uninstall_hook(shell)
            return jsonify({"installed": not removed, "removed": removed})

        return jsonify({"error": "action must be 'install' or 'uninstall'"}), 400

    @app.route("/api/logs/analytics", methods=["GET"])
    def api_logs_analytics():
        log_file = _log_path()
        range_param = request.args.get("range", "all")

        # Parse time range
        now = datetime.now(timezone.utc)
        cutoff = None
        range_hours = {"1h": 1, "6h": 6, "24h": 24, "7d": 168}
        if range_param in range_hours:
            cutoff = now - timedelta(hours=range_hours[range_param])

        # Read and parse log entries
        entries: list[dict] = []
        if log_file.is_file():
            for line in log_file.read_text(encoding="utf-8").strip().splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if cutoff and entry.get("timestamp"):
                    try:
                        ts = datetime.fromisoformat(entry["timestamp"])
                        if ts < cutoff:
                            continue
                    except (ValueError, TypeError):
                        pass
                entries.append(entry)

        # Aggregate metrics
        verdict_counts = Counter(e.get("verdict", "unknown") for e in entries)
        action_type_counts = Counter(e.get("action_type", "unknown") for e in entries)

        # Top rules (deny + warn only)
        deny_warn = [e for e in entries if e.get("verdict") in ("deny", "warn")]
        rule_counts = Counter(e.get("rule", "unknown") for e in deny_warn)
        top_rules = [{
            "rule": rule, "count": count
        } for rule, count in rule_counts.most_common(10)]

        # Top blocked targets (deny + warn only)
        target_counts = Counter(e.get("target", "unknown") for e in deny_warn)
        top_targets = [{
            "target": target, "count": count
        } for target, count in target_counts.most_common(10)]

        # Verdicts over time (bucket by hour)
        time_buckets: dict[str, dict[str, int]] = {}
        for e in entries:
            ts_str = e.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_str)
                bucket = ts.strftime("%Y-%m-%d %H:00")
            except (ValueError, TypeError):
                continue
            if bucket not in time_buckets:
                time_buckets[bucket] = {"allow": 0, "deny": 0, "warn": 0}
            v = e.get("verdict", "")
            if v in time_buckets[bucket]:
                time_buckets[bucket][v] += 1
        sorted_buckets = sorted(time_buckets.keys())
        verdicts_over_time = {
            "labels": sorted_buckets,
            "allow": [time_buckets[b]["allow"] for b in sorted_buckets],
            "deny": [time_buckets[b]["deny"] for b in sorted_buckets],
            "warn": [time_buckets[b]["warn"] for b in sorted_buckets],
        }

        total = len(entries)
        total_deny = verdict_counts.get("deny", 0)
        total_warn = verdict_counts.get("warn", 0)

        return jsonify({
            "total_events": total,
            "total_deny": total_deny,
            "total_warn": total_warn,
            "deny_rate": round(total_deny / total * 100, 1) if total else 0,
            "verdict_counts": dict(verdict_counts),
            "action_type_counts": dict(action_type_counts),
            "top_rules": top_rules,
            "top_targets": top_targets,
            "verdicts_over_time": verdicts_over_time,
        })

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
