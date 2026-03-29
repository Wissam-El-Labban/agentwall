"""Tests for the agentfirewall web UI dashboard."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentfirewall.presets import get_preset
from agentfirewall.schema import CONFIG_FILENAME, DOTFILE_NAME, SUBDIRS, config_to_yaml


@pytest.fixture()
def agentfirewall_dir(tmp_path):
    """Create a minimal .agentfirewall/ directory with standard preset."""
    af_dir = tmp_path / DOTFILE_NAME
    af_dir.mkdir()
    for subdir in SUBDIRS:
        (af_dir / subdir).mkdir()
    config = get_preset("standard")
    (af_dir / CONFIG_FILENAME).write_text(config_to_yaml(config), encoding="utf-8")
    return af_dir


@pytest.fixture()
def app(agentfirewall_dir):
    """Create the Flask test app."""
    from agentfirewall.ui.app import create_app

    app = create_app(config_dir=agentfirewall_dir)
    app.config["TESTING"] = True
    return app


@pytest.fixture()
def client(app):
    return app.test_client()


# ── Page routes ──────────────────────────────────────────────


class TestPages:
    def test_dashboard_returns_200(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"Dashboard" in resp.data

    def test_config_page_returns_200(self, client):
        resp = client.get("/config")
        assert resp.status_code == 200
        assert b"Configuration" in resp.data

    def test_logs_page_returns_200(self, client):
        resp = client.get("/logs")
        assert resp.status_code == 200
        assert b"Audit Logs" in resp.data

    def test_dashboard_shows_mode(self, client):
        resp = client.get("/")
        assert b"enforce" in resp.data

    def test_dashboard_shows_stats(self, client):
        resp = client.get("/")
        assert b"Blocked Commands" in resp.data
        assert b"Protected Paths" in resp.data


# ── API: config ──────────────────────────────────────────────


class TestAPIConfig:
    def test_get_config_returns_json(self, client):
        resp = client.get("/api/config")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["mode"] == "enforce"
        assert "commands" in data
        assert "filesystem" in data
        assert "network" in data

    def test_put_config_changes_mode(self, client, agentfirewall_dir):
        resp = client.put(
            "/api/config",
            data=json.dumps({"mode": "audit"}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["mode"] == "audit"

        # Verify persisted to YAML
        yaml_text = (agentfirewall_dir / CONFIG_FILENAME).read_text()
        assert "mode: audit" in yaml_text

    def test_put_config_changes_blocklist(self, client):
        resp = client.put(
            "/api/config",
            data=json.dumps({"commands": {"blocklist": ["rm -rf /", "drop table"]}}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "drop table" in data["commands"]["blocklist"]

    def test_put_config_no_json_returns_error(self, client):
        resp = client.put("/api/config", data="not json", content_type="text/plain")
        assert resp.status_code in (400, 415)


# ── API: preset ──────────────────────────────────────────────


class TestAPIPreset:
    def test_switch_to_strict(self, client, agentfirewall_dir):
        resp = client.post(
            "/api/preset",
            data=json.dumps({"preset": "strict"}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["mode"] == "enforce"
        assert len(data["commands"]["blocklist"]) > 10  # strict has more entries

    def test_switch_to_permissive(self, client):
        resp = client.post(
            "/api/preset",
            data=json.dumps({"preset": "permissive"}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["mode"] == "audit"

    def test_invalid_preset_returns_400(self, client):
        resp = client.post(
            "/api/preset",
            data=json.dumps({"preset": "nonexistent"}),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_missing_body_returns_error(self, client):
        resp = client.post("/api/preset", data="not json", content_type="text/plain")
        assert resp.status_code in (400, 415)


# ── API: logs ────────────────────────────────────────────────


class TestAPILogs:
    def test_logs_empty(self, client):
        resp = client.get("/api/logs")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["entries"] == []

    def test_logs_with_entries(self, client, agentfirewall_dir):
        log_dir = agentfirewall_dir / "logs"
        log_dir.mkdir(exist_ok=True)
        log_file = log_dir / "firewall.log"
        entries = [
            {"timestamp": "2026-03-28T12:00:00", "action_type": "command",
             "target": "rm -rf /", "verdict": "deny", "rule": "blocklist", "detail": "blocked"},
            {"timestamp": "2026-03-28T12:01:00", "action_type": "command",
             "target": "ls", "verdict": "allow", "rule": "default", "detail": "ok"},
        ]
        log_file.write_text(
            "\n".join(json.dumps(e) for e in entries) + "\n",
            encoding="utf-8",
        )
        resp = client.get("/api/logs")
        data = resp.get_json()
        assert data["total"] == 2

    def test_logs_verdict_filter(self, client, agentfirewall_dir):
        log_dir = agentfirewall_dir / "logs"
        log_dir.mkdir(exist_ok=True)
        log_file = log_dir / "firewall.log"
        entries = [
            {"timestamp": "T1", "action_type": "cmd", "target": "rm", "verdict": "deny", "rule": "r", "detail": "d"},
            {"timestamp": "T2", "action_type": "cmd", "target": "ls", "verdict": "allow", "rule": "r", "detail": "d"},
        ]
        log_file.write_text("\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")

        resp = client.get("/api/logs?verdict=deny")
        data = resp.get_json()
        assert data["total"] == 1
        assert data["entries"][0]["verdict"] == "deny"


# ── API: agents (stubbed) ───────────────────────────────────


class TestAPIAgents:
    def test_agents_returns_empty_list(self, client):
        resp = client.get("/api/agents")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["agents"] == []
        assert data["discovery_available"] is False
