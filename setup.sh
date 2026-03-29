#!/usr/bin/env bash
# setup.sh — Bootstrap script for agentfirewall development environment
#
# Usage:
#   ./setup.sh           # Full setup (system deps + venv + Python deps)
#   ./setup.sh --no-fuse # Skip FUSE/libfuse (sandbox features unavailable)
#
# Requires: Python 3.10+, sudo for system packages.

set -euo pipefail

VENV_DIR="security-env"
INSTALL_FUSE=true

for arg in "$@"; do
    case "$arg" in
        --no-fuse) INSTALL_FUSE=false ;;
        -h|--help)
            echo "Usage: $0 [--no-fuse]"
            echo ""
            echo "  --no-fuse   Skip libfuse installation (FUSE sandbox will be unavailable)"
            exit 0
            ;;
        *) echo "Unknown option: $arg"; exit 1 ;;
    esac
done

echo "==> Checking Python version..."
PYTHON=""
for candidate in python3.10 python3.11 python3.12 python3; do
    if command -v "$candidate" &>/dev/null; then
        version=$("$candidate" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        major="${version%%.*}"
        minor="${version##*.}"
        if [[ "$major" -ge 3 && "$minor" -ge 10 ]]; then
            PYTHON="$candidate"
            break
        fi
    fi
done

if [[ -z "$PYTHON" ]]; then
    echo "ERROR: Python 3.10+ is required but not found."
    echo "Install it with:  sudo apt install python3.10 python3.10-venv"
    exit 1
fi
echo "    Using $PYTHON ($($PYTHON --version 2>&1))"

# ── System dependencies ────────────────────────────────────────

echo ""
echo "==> Installing system dependencies..."

if command -v apt-get &>/dev/null; then
    PKGS=("python3-venv")

    if [[ "$INSTALL_FUSE" == true ]]; then
        PKGS+=("fuse3" "libfuse-dev")
    fi

    sudo apt-get update -qq
    sudo apt-get install -y -qq "${PKGS[@]}"

    if [[ "$INSTALL_FUSE" == true ]]; then
        echo "    libfuse2 installed (required by fusepy for FUSE sandbox)"
    fi
elif command -v dnf &>/dev/null; then
    PKGS=()
    if [[ "$INSTALL_FUSE" == true ]]; then
        PKGS+=("fuse" "fuse-devel")
    fi
    if [[ ${#PKGS[@]} -gt 0 ]]; then
        sudo dnf install -y "${PKGS[@]}"
    fi
elif command -v brew &>/dev/null; then
    if [[ "$INSTALL_FUSE" == true ]]; then
        echo "    macOS: Install macFUSE from https://osxfuse.github.io/"
        echo "    Then run: brew install macfuse"
    fi
else
    echo "    WARNING: Unrecognized package manager. Install dependencies manually."
    if [[ "$INSTALL_FUSE" == true ]]; then
        echo "    Needed: libfuse2 / libfuse-dev (for FUSE sandbox support)"
    fi
fi

# ── Python virtual environment ─────────────────────────────────

echo ""
echo "==> Setting up Python virtual environment ($VENV_DIR/)..."

if [[ ! -d "$VENV_DIR" ]]; then
    $PYTHON -m venv "$VENV_DIR"
    echo "    Created $VENV_DIR/"
else
    echo "    $VENV_DIR/ already exists, reusing"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

# ── Python dependencies ────────────────────────────────────────

echo ""
echo "==> Installing Python dependencies..."

pip install --upgrade pip --quiet

if [[ "$INSTALL_FUSE" == true ]]; then
    pip install -e ".[dev,sandbox,ui]" --quiet
    echo "    Installed: core + dev + sandbox (fusepy) + ui (Flask)"
else
    pip install -e ".[dev,ui]" --quiet
    echo "    Installed: core + dev + ui (Flask) (no FUSE sandbox)"
fi

# ── Verify ─────────────────────────────────────────────────────

echo ""
echo "==> Verifying installation..."

# Core
$PYTHON -c "import agentfirewall; print(f'    agentfirewall {agentfirewall.__version__}')"

# FUSE check
if [[ "$INSTALL_FUSE" == true ]]; then
    if $PYTHON -c "import fuse" 2>/dev/null; then
        echo "    fusepy + libfuse OK"
    else
        echo "    WARNING: fusepy installed but libfuse not loadable."
        echo "    The FUSE sandbox will not work. Install libfuse-dev manually."
    fi
fi

# Tests
echo ""
echo "==> Running tests..."
pytest -v --tb=short

echo ""
echo "=========================================="
echo "  Setup complete!"
echo ""
echo "  Activate the environment with:"
echo "    source $VENV_DIR/bin/activate"
echo ""
echo "  Quick start:"
echo "    agentfirewall init"
echo "    agentfirewall check \"rm -rf /\""
echo "    agentfirewall status"
if [[ "$INSTALL_FUSE" == true ]]; then
echo "    agentfirewall sandbox  # FUSE sandbox"
fi
echo "=========================================="
