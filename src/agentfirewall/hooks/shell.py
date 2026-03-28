"""Shell preexec hook generation, installation, and removal."""

from __future__ import annotations

import os
from pathlib import Path

GUARD_BEGIN = "# >>> agentfirewall >>>"
GUARD_END = "# <<< agentfirewall <<<"

_BASH_HOOK = """\
# >>> agentfirewall >>>
shopt -s extdebug
__agentfirewall_preexec() {
    [[ "$BASH_COMMAND" == agentfirewall* ]] && return 0
    [[ "$BASH_COMMAND" == agentwall* ]] && return 0
    agentfirewall check "$BASH_COMMAND" > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "[agentfirewall] BLOCKED: $BASH_COMMAND" >&2
        return 1
    fi
}
trap '__agentfirewall_preexec' DEBUG
# <<< agentfirewall <<<
"""

_ZSH_HOOK = """\
# >>> agentfirewall >>>
__agentfirewall_preexec() {
    [[ "$1" == agentfirewall* ]] && return 0
    [[ "$1" == agentwall* ]] && return 0
    agentfirewall check "$1" > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "[agentfirewall] BLOCKED: $1" >&2
        kill -INT $$
    fi
}
autoload -Uz add-zsh-hook
add-zsh-hook preexec __agentfirewall_preexec
# <<< agentfirewall <<<
"""


def generate_bash_hook() -> str:
    """Return the bash preexec hook snippet."""
    return _BASH_HOOK


def generate_zsh_hook() -> str:
    """Return the zsh preexec hook snippet."""
    return _ZSH_HOOK


def detect_shell() -> str:
    """Detect the user's shell from $SHELL. Returns 'bash' or 'zsh'."""
    shell = os.environ.get("SHELL", "")
    if "zsh" in shell:
        return "zsh"
    return "bash"


def _rc_path_for_shell(shell: str) -> Path:
    """Return the default RC file path for a shell."""
    home = Path.home()
    if shell == "zsh":
        return home / ".zshrc"
    return home / ".bashrc"


def install_hook(shell: str | None = None, rc_path: Path | None = None) -> Path:
    """Install the preexec hook into the shell RC file.

    Returns the path of the modified RC file.
    Idempotent: if guard markers are already present, does nothing.
    """
    shell = shell or detect_shell()
    rc = rc_path or _rc_path_for_shell(shell)

    # Check if already installed
    if rc.exists():
        content = rc.read_text(encoding="utf-8")
        if GUARD_BEGIN in content:
            return rc
    else:
        content = ""

    hook = generate_zsh_hook() if shell == "zsh" else generate_bash_hook()
    # Ensure newline before hook block
    if content and not content.endswith("\n"):
        content += "\n"
    content += hook

    rc.write_text(content, encoding="utf-8")
    return rc


def uninstall_hook(shell: str | None = None, rc_path: Path | None = None) -> bool:
    """Remove the preexec hook from the shell RC file.

    Returns True if the hook was found and removed, False if not present.
    """
    shell = shell or detect_shell()
    rc = rc_path or _rc_path_for_shell(shell)

    if not rc.exists():
        return False

    content = rc.read_text(encoding="utf-8")
    if GUARD_BEGIN not in content:
        return False

    # Remove everything between (and including) guard markers
    lines = content.splitlines(keepends=True)
    new_lines: list[str] = []
    inside_guard = False
    for line in lines:
        if GUARD_BEGIN in line:
            inside_guard = True
            continue
        if GUARD_END in line:
            inside_guard = False
            continue
        if not inside_guard:
            new_lines.append(line)

    rc.write_text("".join(new_lines), encoding="utf-8")
    return True
