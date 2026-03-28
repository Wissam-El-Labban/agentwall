# Agentwall

Protect your system from destructive AI agent actions.

When AI agents like Claude Code, Cursor, or Copilot run on your machine, they can delete files, overwrite code, or leak data. Agentwall blocks dangerous actions before they happen.

---

## Install

```bash
pip install agentwall
```

---

## Usage

**Protect a project:**
```bash
cd your-project
agentfirewall protect
```

Then activate the hook in your current terminal:
```bash
source ~/.bashrc  # or ~/.zshrc
```

**Check it's working:**
```bash
agentfirewall status
```

**Stop protection:**
```bash
agentfirewall unprotect
```

---

## What it does

- **Blocks dangerous terminal commands** before they run (`rm -rf /`, `git reset --hard`, etc.)
- **Monitors your files** in real time and kills the agent if it touches protected files
- **Logs everything** to `.agentfirewall/logs/firewall.log`

---

## Presets

```bash
agentfirewall protect --preset standard     # default — blocks common dangerous commands
agentfirewall protect --preset strict       # blocks more, no sandbox escape
agentfirewall protect --preset permissive   # warns only, never blocks
```

---

## Requirements

- Python 3.10+
- Linux or macOS (Windows: use WSL)

---

## Optional: deeper protection (Linux/macOS only)

Install the FUSE sandbox for OS-level blocking:

```bash
# Ubuntu/Debian
sudo apt install fuse3 libfuse-dev
pip install agentwall[sandbox]

# macOS
brew install macfuse
pip install agentwall[sandbox]

# Then run inside the sandbox
agentfirewall sandbox python your_agent.py
```

---

## License

MIT
