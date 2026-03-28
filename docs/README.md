# Agent Firewall — Technical Documentation

## Overview

`agentfirewall` is a filesystem-level security tool that protects your OS from destructive LLM agent tool calls. It works as a hidden `.agentfirewall/` directory (similar to `.git/`) placed at the root of any project, defining rules that govern what commands, file operations, and network connections an agent is allowed to perform.

**Current status:** Phase 1 (static rule checker) and Phase 2 (real-time OS enforcement) are complete. The tool evaluates actions against YAML-defined rules, returns allow/deny/warn verdicts, monitors the filesystem in real time, intercepts shell commands before execution, and kills offending agent processes.

---

## How It Works — Two-Layer Defense

The firewall protects your project through two independent layers that work together:

```
 Agent tries something destructive
            │
    ┌───────▼────────┐
    │  LAYER 1:      │   Shell hooks intercept every command BEFORE it runs.
    │  Prevention    │   bash DEBUG trap / zsh preexec calls "agentfirewall check".
    │  (hooks/)      │   If denied → command never executes.
    └───────┬────────┘
            │ command allowed (or agent bypasses shell entirely,
            │ e.g. Python os.remove(), Node fs.unlink())
    ┌───────▼────────┐
    │  LAYER 2:      │   Filesystem watcher (watchdog) monitors all file events.
    │  Detection &   │   Evaluates each event against engine rules.
    │  Retaliation   │   If denied → kills the agent process via psutil.
    │  (watchers/)   │
    └───────┬────────┘
            │
    ┌───────▼────────┐
    │  Audit Log     │   Both layers log every decision (allow/deny/warn)
    │  (audit.py)    │   as structured JSON to .agentfirewall/logs/firewall.log
    └────────────────┘
```

**Why two layers?** Shell hooks can only intercept commands typed into a shell. If an LLM agent uses a programming language's file APIs directly (e.g., `os.remove()` in Python, `fs.unlinkSync()` in Node), the shell never sees it. The filesystem watcher catches those operations at the OS level.

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                         cli.py                           │
│  (Click commands: init, check, status, watch, hooks)     │
└──┬────────┬────────┬──────────┬──────────┬───────────────┘
   │        │        │          │          │
   │ uses   │ uses   │ uses     │ uses     │ uses
   │        │        │          │          │
   ▼        │        ▼          ▼          ▼
presets/    │    hooks/     watchers/    process.py
__init__.py │    shell.py   filesystem   (kill agents)
(rule sets) │    (bash/zsh   .py            │
            │     hooks)   (watchdog)       │
            │                  │      ┌─────┘
            ▼                  ▼      ▼
        ┌──────────────────────────────────┐
        │            engine.py             │
        │   (Rule evaluation — verdicts)   │
        │        ▲               │         │
        │   uses │          logs │         │
        │        │               ▼         │
        │   schema.py       audit.py       │
        │   (YAML config)   (JSON logger)  │
        └──────────────────────────────────┘
```

Dependencies flow **one direction only** — no circular imports:
- `schema.py` → foundation (no internal imports)
- `engine.py` → imports `schema`
- `audit.py` → imports `engine` (for `RuleResult` type)
- `process.py` → standalone (uses `psutil`)
- `hooks/shell.py` → standalone (reads `$SHELL`, writes RC files)
- `watchers/filesystem.py` → imports `engine`, `schema`, `process`
- `cli.py` → imports everything above

---

## `.agentfirewall/` Directory Structure

```
.agentfirewall/
├── config.yaml     # Main configuration (rules, mode, sandbox settings)
├── rules/          # Custom rule files (reserved for future use)
├── logs/           # Audit logs (firewall.log lives here)
│   └── firewall.log  # Structured JSON log — one entry per line
├── hooks/          # Shell hook scripts (reserved for future use)
└── plugins/        # Extension plugins (reserved for future use)
```

Created by `agentfirewall init`. The directory is discovered by walking up from the current working directory (like `.git/`).

---

## Core Files

### `schema.py` — Data Model

Defines all data structures and handles YAML config parsing/validation/serialization.

**Enums:**
- `FirewallMode` — `ENFORCE` | `AUDIT` | `OFF`
  - ENFORCE: deny actions that violate rules
  - AUDIT: log violations as warnings but allow them
  - OFF: disable all checks
- `DenyOperation` — `DELETE` | `CHMOD` | `MOVE_OUTSIDE_SANDBOX` | `WRITE`

**Dataclasses (the config tree):**
- `FirewallConfig` — top-level container (version, mode, and all sub-configs)
  - `SandboxConfig` — defines the allowed working directory (`root`) and whether escaping is permitted
  - `FilesystemConfig` — protected path patterns (globs) and which operations are denied on them
  - `CommandsConfig` — blocklist and allowlist of shell command patterns
  - `NetworkConfig` — allowed hosts, denied egress targets, max upload size
  - `LoggingConfig` — log file location and level

**Constants:**
- `DOTFILE_NAME = ".agentfirewall"` — directory name
- `CONFIG_FILENAME = "config.yaml"` — config file within the directory
- `SUBDIRS = ["rules", "logs", "hooks", "plugins"]` — subdirectories created on init

**Key Functions:**
- `find_config(start_dir)` — walks up from `start_dir` (default: CWD) looking for a `.agentfirewall/` directory containing `config.yaml`. Returns the path to `config.yaml` or `None`.
- `load_config(path)` — reads and validates a YAML file into a `FirewallConfig`. Uses `yaml.safe_load` for security. Raises `ConfigError` on invalid input.
- `default_config()` — returns a `FirewallConfig` with sensible defaults (15 blocklist patterns, 3 allowed hosts).
- `config_to_yaml(config)` — serializes a `FirewallConfig` back to YAML text.

---

### `engine.py` — Rule Evaluation

The decision-making core. Takes a `FirewallConfig` and evaluates actions against it.

**Data Types:**
- `Verdict` enum — `ALLOW` | `DENY` | `WARN`
- `RuleResult` dataclass — contains `verdict`, `rule` (which rule triggered), `detail` (human-readable explanation), and a `blocked` property (True only for DENY)

**`Engine` class:**

Constructor takes a `FirewallConfig` and an optional `AuditLogger`. It pre-compiles all blocklist/allowlist patterns into regex objects for performance. When an `AuditLogger` is provided, every evaluation call automatically logs the decision.

Three evaluation methods:

1. **`evaluate_command(command)`** — checks a shell command string
   - If mode is OFF → ALLOW
   - If allowlist is non-empty and command doesn't match → DENY
   - If command matches any blocklist pattern → DENY
   - Otherwise → ALLOW
   - Allowlist takes priority (checked first)

2. **`evaluate_file_operation(operation, path)`** — checks a filesystem operation
   - If mode is OFF → ALLOW
   - Sandbox boundary check: resolves the path against `sandbox.root` and verifies it stays within bounds. Relative paths are resolved against the sandbox root (not CWD) to prevent bypass.
   - Protected paths check: if the operation is in `deny_operations` and the path matches any `protected_paths` glob → DENY
   - Otherwise → ALLOW

3. **`evaluate_network(host)`** — checks an outbound connection
   - If mode is OFF → ALLOW
   - If host is in `deny_egress_to` → DENY
   - If `allowed_hosts` is set and host isn't listed → DENY
   - Otherwise → ALLOW

**Internal helpers:**
- `_make_result()` — in AUDIT mode, downgrades DENY → WARN (with `[AUDIT]` prefix in detail)
- `_compile_command_pattern()` — converts glob-style patterns (e.g., `rm -rf *`) to regex by escaping everything except `*`, then replacing `*` with `.*`
- `_path_matches()` — matches paths against glob patterns using both the full path and just the filename

---

### `cli.py` — Command-Line Interface

Click-based CLI with 10 commands:

| Command | Description | Exit Code |
|---------|-------------|-----------|
| `protect` | One-command setup: init + install hooks + start background watcher | 0 or 1 |
| `unprotect` | One-command teardown: stop watcher + remove hooks | 0 |
| `init` | Create `.agentfirewall/` with config and subdirectories | 0 or 1 |
| `check <command>` | Dry-run: check if a shell command would be allowed | 0=allow, 1=deny |
| `check-file <path>` | Dry-run: check if a file operation would be allowed | 0=allow, 1=deny |
| `check-network <host>` | Dry-run: check if a network connection would be allowed | 0=allow, 1=deny |
| `status` | Show current firewall config, watcher state, and hooks state | 0 |
| `watch` | Start real-time filesystem monitoring (Ctrl+C to stop) | 0 or 1 |
| `install-hooks` | Install shell preexec hooks for command interception | 0 |
| `uninstall-hooks` | Remove shell preexec hooks | 0 |

**`protect` command details:**
- Accepts `--preset` (standard/strict/permissive), `--shell` (bash/zsh), and `--force` flags
- Runs `init`, installs shell hooks, and starts `watch` as a background process
- Saves the watcher PID to `.agentfirewall/watcher.pid` so `unprotect` can stop it later
- Errors if `.agentfirewall/` already exists (unless `--force`)

**`unprotect` command details:**
- Reads `.agentfirewall/watcher.pid` and sends SIGTERM to stop the background watcher
- Removes shell hooks from `~/.bashrc` or `~/.zshrc`
- `--remove-config` flag also deletes the `.agentfirewall/` directory entirely
- Handles gracefully if watcher is already stopped or PID file is missing

**`init` command details:**
- Accepts `--preset` (standard/strict/permissive) and `--force` flags
- Creates the `.agentfirewall/` directory + all subdirectories (`rules/`, `logs/`, `hooks/`, `plugins/`)
- Writes `config.yaml` from the selected preset
- Errors if directory already exists (unless `--force`)

**`watch` command details:**
- Loads the nearest `.agentfirewall/` config
- Creates an `AuditLogger`, wires it into an `Engine`, creates a `ProcessKiller`
- Starts a `FirewallObserver` that monitors the sandbox directory
- Runs in the foreground until Ctrl+C

**`install-hooks` / `uninstall-hooks` details:**
- Accept `--shell bash|zsh` (auto-detected if omitted)
- Install appends a guard-marked hook block to `~/.bashrc` or `~/.zshrc`
- Uninstall removes only the guard-marked block, preserving all other content

**`_load_engine()`** — shared helper that calls `find_config()` then `load_config()` then creates an `Engine`. Returns `None` if no config found.

---

### `audit.py` — Structured Audit Logging

Writes every firewall decision (allow, deny, warn) as a JSON log entry to `.agentfirewall/logs/firewall.log`.

**`AuditLogger` class:**
- Constructor: `AuditLogger(config: LoggingConfig, base_dir: Path)`
- Creates the log directory if it doesn't exist
- Uses Python's `RotatingFileHandler` (5 MB per file, 3 backup files)
- Uses a custom `_JsonFormatter` that outputs one JSON object per line

**Log entry format (one per line):**
```json
{"timestamp": "2026-03-27T14:30:00Z", "action_type": "command", "target": "rm -rf /", "verdict": "deny", "rule": "blocklist", "detail": "Matches blocklist pattern: rm -rf /"}
```

**Log level filtering:**
The `level` in `LoggingConfig` controls which verdicts are logged:
- `"info"` — logs everything (ALLOW + DENY + WARN)
- `"warn"` (default) — logs DENY and WARN only, skips ALLOW
- `"error"` — logs DENY only

If `logging.enabled` is `false`, the logger is created but writes nothing.

---

### `process.py` — Agent Process Killer

Identifies and terminates running LLM agent processes. Called by the filesystem watcher when a rule violation is detected.

**`ProcessKiller` class:**
- Constructor: `ProcessKiller(signatures: list[str] | None = None)` — custom signatures override defaults
- `find_agent_processes()` — scans all running processes via `psutil`
- `kill_agents()` — finds and terminates agent processes, returns count killed

**Agent identification — two tiers:**

*Exact signatures* (process name contains any of these):
`claude`, `cursor`, `copilot-agent`, `windsurf`, `aider`

*Broad signatures* (process name matches, but only if the full command line also contains an agent keyword):
`node`, `code` — these are too common on their own, so the killer checks the full command line for agent-related strings before killing.

**Safety guards:**
- Never kills PID 0 or PID 1 (init/kernel)
- Never kills its own process or its parent process
- Gracefully handles `NoSuchProcess` (process died between scan and kill)
- Gracefully handles `AccessDenied` (insufficient permissions)

---

### `watchers/filesystem.py` — Real-Time Filesystem Monitor

Uses the `watchdog` library to monitor directory trees for file events, then evaluates each event against the engine rules.

**`FirewallHandler(FileSystemEventHandler)` class:**
- Receives filesystem events from watchdog
- Maps events to engine operations:

| Watchdog Event | → | Engine DenyOperation |
|----------------|---|---------------------|
| `FileDeletedEvent` | → | `DELETE` |
| `FileModifiedEvent` | → | `WRITE` |
| `FileMovedEvent` | → | `MOVE_OUTSIDE_SANDBOX` |

- Converts absolute paths (from watchdog) to relative paths (for engine pattern matching) using the watch root directory
- Ignores all events inside `.agentfirewall/` itself (prevents self-triggering)
- Ignores directory-level events (only monitors files)
- On DENY verdict: prints a formatted violation alert to stderr (emoji, verdict, operation, path, rule, detail), calls `ProcessKiller.kill_agents()` to terminate the offending agent, and prints the kill count
- On ALLOW verdict: no output (silent pass-through)

**`FirewallObserver` class:**
- Wraps watchdog's `Observer` with agentfirewall-specific setup
- `start()` — begins watching the sandbox root recursively
- `stop()` — stops the observer
- `run_forever()` — starts and blocks until Ctrl+C (used by the `watch` CLI command)

---

### `hooks/shell.py` — Shell Preexec Hooks

Generates, installs, and removes shell hook scripts that intercept commands before they execute.

**How the hooks work:**
- **Bash:** Enables `extdebug` mode (`shopt -s extdebug`) and installs a `DEBUG` trap. Before every command, bash calls `agentfirewall check "$BASH_COMMAND"`. If the exit code is non-zero (denied), the hook prints `[agentfirewall] BLOCKED: <command>` to stderr and returns 1 — with `extdebug` enabled, a non-zero return from a DEBUG trap **prevents the command from executing**. Without `extdebug`, bash ignores the return value and runs the command anyway.
- **Zsh:** Uses `add-zsh-hook preexec`. Checks the command via `agentfirewall check "$1"`. If denied, prints the BLOCKED message and sends `kill -INT $$` (SIGINT to self) to abort the pending command. Zsh's `preexec` is a notification hook — `return 1` alone doesn't stop execution — so the self-interrupt is required.

**Guard markers:**
Hook blocks are wrapped in `# >>> agentfirewall >>>` and `# <<< agentfirewall <<<` markers (similar to how conda manages shell integration). This allows:
- **Idempotent install** — if markers already exist, `install_hook()` does nothing
- **Clean uninstall** — `uninstall_hook()` removes only the guarded block, preserving all other RC file content

**Functions:**
- `generate_bash_hook()` / `generate_zsh_hook()` — return the hook script strings
- `detect_shell()` — reads `$SHELL` env var, returns `"bash"` or `"zsh"`
- `install_hook(shell, rc_path)` — appends hook to `~/.bashrc` or `~/.zshrc`
- `uninstall_hook(shell, rc_path)` — removes the guard-marked block

---

### `presets/__init__.py` — Built-in Rule Sets

Three presets with increasing strictness:

**Common blocklist patterns (shared by all presets):**
`rm -rf /`, `rm -rf ~`, `rm -rf /*`, `dd if=*of=/dev/*`, `mkfs.*`, `:(){ :|:& };:`, `chmod -R 777`, `sudo rm*`, `git push --force`, `git push.*--force`, `git reset --hard`, `git clean -fd`, `kill -9`

| Feature | Standard | Strict | Permissive |
|---------|----------|--------|------------|
| Mode | ENFORCE | ENFORCE | AUDIT |
| Blocklist | 13 common patterns | 23 patterns (common + extra) | 13 common patterns |
| Protected paths | .git/**, .env, .ssh/** | + /etc/**, /boot/**, /usr/** | .git/**, .env, .ssh/** |
| Sandbox escape | Allowed | **Blocked** | Allowed |
| Deny operations | delete, move_outside | + chmod, write | delete, move_outside |
| Allowed hosts | github.com, OpenAI, Anthropic | Same | *(none — all allowed)* |
| Logging | Enabled (warn level) | Enabled (warn level) | Enabled (warn level) |

**Extra strict blocklist additions:** `curl*|*bash`, `wget*|*sh`, `eval *`, `exec *`, `python -c*`, `node -e*`, `nc *`, `ncat *`, `netcat *`, `telnet *`

**API:**
- `get_preset(name)` — returns a `FirewallConfig` for the named preset
- `list_presets()` — returns `["standard", "strict", "permissive"]`

---

## Config Schema (YAML)

```yaml
version: 1
mode: enforce          # enforce | audit | off

sandbox:
  root: "."            # Working directory boundary
  allow_escape: false  # Allow operations outside sandbox root

filesystem:
  protected_paths:     # Glob patterns for protected files
    - ".git/**"
    - ".env"
    - ".ssh/**"
  deny_operations:     # Operations blocked on protected paths
    - delete
    - move_outside_sandbox

commands:
  blocklist:           # Shell command patterns to block (* = wildcard)
    - "rm -rf /"
    - "sudo rm*"
  allowlist: []        # If non-empty, ONLY these commands are allowed

network:
  allowed_hosts:       # If non-empty, only these hosts permitted
    - "github.com"
    - "api.openai.com"
  deny_egress_to:      # Always blocked regardless of allowed_hosts
    - "169.254.169.254"
    - "metadata.google.internal"
  max_upload_bytes: 10485760  # 10 MB (not yet enforced)

logging:
  enabled: true
  file: "logs/firewall.log"
  level: warn
```

---

## Decision Logic Summary

```
Command Check:
  mode=OFF? → ALLOW
  allowlist non-empty AND command not in allowlist? → DENY
  command matches blocklist? → DENY
  else → ALLOW

File Operation Check:
  mode=OFF? → ALLOW
  path escapes sandbox (and allow_escape=false)? → DENY
  operation in deny_operations AND path matches protected_paths? → DENY
  else → ALLOW

Network Check:
  mode=OFF? → ALLOW
  host in deny_egress_to? → DENY
  allowed_hosts non-empty AND host not in allowed_hosts? → DENY
  else → ALLOW

In all cases: if mode=AUDIT, DENY is downgraded to WARN.
```

---

## Test Structure

109 tests across 10 files (all passing):

| File | Tests | What it covers |
|------|-------|----------------|
| `tests/test_schema.py` | 12 | Config loading, validation, YAML round-trip, find_config directory walking, error handling |
| `tests/test_engine.py` | 25 | Command evaluation (blocklist, allowlist, wildcards), file operations (sandbox boundary, protected paths), network checks, audit mode downgrade, mode=off bypass |
| `tests/test_cli.py` | 14 | CLI init (directory creation, presets, --force), check/check-file/check-network commands, status output, missing config errors |
| `tests/test_presets.py` | 5 | Preset content validation, list_presets, unknown preset error |
| `tests/test_audit.py` | 10 | Log file creation, JSON format, multiple entries, disabled logging, level filtering, timestamp format |
| `tests/test_process.py` | 14 | Agent detection (exact + broad signatures), PID safety guards, kill count, AccessDenied/NoSuchProcess handling |
| `tests/test_watcher.py` | 10 | Delete/modify/move event handling, protected path triggers, allow normal ops, process killer calls, .agentfirewall/ ignoring, directory event ignoring |
| `tests/test_hooks.py` | 14 | Hook generation (bash/zsh), shell detection, install to new/existing files, idempotency, uninstall with content preservation |
| `tests/test_cli_phase2.py` | 6 | watch command (starts observer, no-config error), install-hooks (bash/zsh), uninstall-hooks (remove/not-present) |

Run tests: `pytest -v` (from project root with venv activated)

---

## Quick Start

The fastest way to get everything set up (system deps + venv + Python packages):

```bash
git clone <repo-url> && cd llm-security
./setup.sh              # Full setup including FUSE sandbox support
./setup.sh --no-fuse    # Skip FUSE if you don't need the sandbox
```

Or install manually:

```bash
# System dependencies (for FUSE sandbox — skip if not needed)
sudo apt install fuse3 libfuse-dev   # Debian/Ubuntu
sudo dnf install fuse fuse-devel     # Fedora/RHEL

# Install in development mode
pip install -e ".[dev]"              # Core + tests
pip install -e ".[dev,sandbox]"      # Core + tests + FUSE sandbox

# --- One-command setup (recommended) ---

# Protect your project (init + hooks + background watcher in one step)
cd /path/to/your/project
agentfirewall protect                        # standard preset
agentfirewall protect --preset strict        # stricter rules
agentfirewall protect --preset permissive    # warn-only mode

# Disable protection (stops watcher + removes hooks)
agentfirewall unprotect
agentfirewall unprotect --remove-config      # also deletes .agentfirewall/

# View current status (shows mode, watcher state, hooks state)
agentfirewall status

# --- Manual setup (advanced) ---

# Initialize firewall in your project
agentfirewall init                    # standard preset
agentfirewall init --preset strict    # stricter rules

# Check commands before executing
agentfirewall check "rm -rf /"        # 🚫 DENY
agentfirewall check "ls -la"          # ✅ ALLOW

# Check file operations
agentfirewall check-file .env -o delete    # 🚫 DENY
agentfirewall check-file readme.md -o write # ✅ ALLOW

# Check network connections
agentfirewall check-network github.com              # ✅ ALLOW
agentfirewall check-network 169.254.169.254          # 🚫 DENY

# Start real-time filesystem monitoring
agentfirewall watch                   # Ctrl+C to stop

# Install shell hooks (intercept commands before execution)
agentfirewall install-hooks           # auto-detects bash/zsh
agentfirewall install-hooks --shell zsh

# Remove shell hooks
agentfirewall uninstall-hooks
```

---

## Dependencies

### System Requirements

| Package | Platform | Purpose | Required? |
|---------|----------|---------|----------|
| `libfuse-dev` | Debian/Ubuntu | Provides `libfuse.so.2` for FUSE sandbox (`agentfirewall sandbox`) | Only for sandbox feature |
| `fuse3` | Debian/Ubuntu | FUSE utilities (`fusermount`) | Only for sandbox feature |
| `fuse-devel` | Fedora/RHEL | Equivalent of `libfuse-dev` | Only for sandbox feature |
| `macfuse` | macOS | macOS FUSE support ([osxfuse.github.io](https://osxfuse.github.io/)) | Only for sandbox feature |

> **Note:** `fusepy` (the Python binding) requires FUSE 2 (`libfuse.so.2`), **not** FUSE 3. On systems with only `libfuse3`, install `libfuse-dev` to get the FUSE 2 library — both coexist safely.

### Python Packages

| Package | Version | Purpose |
| `pyyaml` | ≥ 6.0 | Parse `.agentfirewall/config.yaml` (uses `safe_load` for security) |
| `click` | ≥ 8.0 | CLI framework (commands, options, argument parsing) |
| `watchdog` | ≥ 3.0 | Cross-platform filesystem monitoring (abstracts inotify/fsevents/ReadDirectoryChanges) |
| `psutil` | ≥ 5.9 | Cross-platform process scanning and termination (agent killing) |
| `fusepy` | ≥ 3.0 | FUSE filesystem bindings for sandbox (`pip install agentfirewall[sandbox]`) — *optional* |

Dev dependencies: `pytest` ≥ 7.0, `pytest-cov` ≥ 4.0

---

## Developer Onboarding

### Reading Order

If you're new to the codebase, read the source files in this order — each one builds on the previous:

1. **`schema.py`** — Start here. This is the data model. Learn the config structure (`FirewallConfig` and its sub-configs) and how YAML is parsed. No internal dependencies.
2. **`engine.py`** — The decision maker. Takes a config and evaluates commands/files/network against it. Returns `RuleResult` with a verdict. Depends only on `schema.py`.
3. **`presets/__init__.py`** — Three built-in configs (standard/strict/permissive). Shows how configs are constructed in code. Depends on `schema.py`.
4. **`audit.py`** — JSON structured logging. Wraps Python's `logging` module. Depends on `engine.py` (for the `RuleResult` type).
5. **`process.py`** — Agent process identification and killing. Standalone module — only uses `psutil`.
6. **`watchers/filesystem.py`** — Filesystem monitoring. Connects watchdog events → engine evaluation → process killing. Depends on `engine.py`, `schema.py`, `process.py`.
7. **`hooks/shell.py`** — Shell hook generation and RC file management. Standalone module — only uses `os` and `pathlib`.
8. **`cli.py`** — The user interface. Ties everything together into Click commands. Read this last — it imports from all other modules.

### Module Dependency Graph

```
schema.py ◄──── engine.py ◄──── audit.py
    ▲               ▲               │
    │               │               │ (logged by)
    │               │               ▼
presets/        watchers/      .agentfirewall/
__init__.py     filesystem.py  logs/firewall.log
                    │
                    ├──── process.py  (standalone)
                    │
                    ▼
              hooks/shell.py  (standalone)

                    ▲
                    │ all wired together by
                    │
                 cli.py
```

Arrows point from **dependent → dependency** (e.g., engine imports schema).

### How to Add a New Rule Type

1. Add a new evaluation method to `Engine` in `engine.py` (e.g., `evaluate_dns(hostname)`)
2. If it needs new config fields, add a new dataclass to `schema.py` and wire it into `FirewallConfig` + the YAML parser
3. Add the corresponding `action_type` string to audit log calls (e.g., `self._log("dns", hostname, result)`)
4. Add a CLI command in `cli.py` (e.g., `check-dns`)
5. Add tests in `tests/test_engine.py` and `tests/test_cli.py`

### How to Add a New Watcher Event Type

1. Add the new `DenyOperation` variant to the enum in `schema.py`
2. Map the watchdog event to the new operation in `_EVENT_TO_OP` in `watchers/filesystem.py`
3. Handle the event in `FirewallHandler` (implement the `on_*` method)
4. Add tests in `tests/test_watcher.py`

### Running Tests

```bash
# Activate the virtual environment
source security-env/bin/activate

# Run all tests with verbose output
pytest -v

# Run a specific test file
pytest tests/test_engine.py -v

# Run with coverage
pytest --cov=agentfirewall --cov-report=term-missing

# Run only FUSE sandbox tests (requires libfuse-dev)
pytest tests/test_sandbox.py -v

# Run everything except FUSE sandbox tests
pytest -v --ignore=tests/test_sandbox.py
```

> **Note:** FUSE sandbox tests (`test_sandbox.py`) require `libfuse-dev` to be installed. If only `libfuse3` is present, these tests will fail with `OSError: Unable to find libfuse`. Run `sudo apt install libfuse-dev` to fix, or use `./setup.sh` which handles this automatically.

---

## Roadmap

- **Phase 1** ✅ — Static rule checker (schema, engine, CLI dry-run commands, presets)
- **Phase 2** ✅ — Real-time OS enforcement (audit logging, filesystem watcher, process killer, shell hooks)
- **Phase 3** — Network interception (eBPF/iptables egress filtering, HTTP inspection)
- **Phase 4** — Agent protocol integration (MCP middleware, LangChain callbacks)
- **Phase 5** — Advanced features (ML anomaly detection, multi-agent policies)
- **Phase 6** — Web UI dashboard (Flask, live log viewer, config editor)
