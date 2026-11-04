#!/bin/bash
# Compatible with the Bash 3.2 supplied by macOS. Installs only in this project.
set -euo pipefail
umask 077

AIVI_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
AIVI_DEV=0
case "${1:-}" in
    --dev) AIVI_DEV=1 ;;
    --help|-h)
        echo "Usage: $0 [--dev]"
        echo "Install project-local Python and locked dependencies, then initialize the database."
        exit 0 ;;
    "") ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
esac
if [ "$#" -gt 1 ]; then
    echo "Expected at most one option; use --help." >&2
    exit 2
fi
if [ "$(uname -s)" != Darwin ]; then
    echo "This setup script is for macOS. See README.md for other platforms." >&2
    exit 1
fi
case "$(uname -m)" in
    arm64|x86_64) ;;
    *) echo "Unsupported Mac architecture: $(uname -m)" >&2; exit 1 ;;
esac
if [ "$(sw_vers -productVersion | cut -d. -f1)" -lt 12 ]; then
    echo "The locked native dependencies require macOS 12 or newer." >&2
    exit 1
fi

cd "$AIVI_ROOT"
if [ -x "$AIVI_ROOT/.bootstrap/bin/uv" ]; then
    AIVI_UV="$AIVI_ROOT/.bootstrap/bin/uv"
elif command -v uv >/dev/null 2>&1; then
    AIVI_UV="$(command -v uv)"
else
    AIVI_BOOTSTRAP_PYTHON="${AIVI_BOOTSTRAP_PYTHON:-python3}"
    if ! command -v "$AIVI_BOOTSTRAP_PYTHON" >/dev/null 2>&1; then
        echo "Install uv (brew install uv) or Python 3 with venv/pip, then rerun this script." >&2
        exit 1
    fi
    "$AIVI_BOOTSTRAP_PYTHON" -m venv "$AIVI_ROOT/.bootstrap"
    "$AIVI_ROOT/.bootstrap/bin/python" -m pip install --disable-pip-version-check 'uv==0.9.7'
    AIVI_UV="$AIVI_ROOT/.bootstrap/bin/uv"
fi

export UV_PYTHON_INSTALL_DIR="$AIVI_ROOT/.python"
export UV_CACHE_DIR="$AIVI_ROOT/.cache/uv"
export UV_PROJECT_ENVIRONMENT="$AIVI_ROOT/.venv"
AIVI_PYTHON_VERSION="$(cat "$AIVI_ROOT/.python-version")"
"$AIVI_UV" python install --no-bin "$AIVI_PYTHON_VERSION"
AIVI_PYTHON="$("$AIVI_UV" python find --managed-python --no-project "$AIVI_PYTHON_VERSION")"
# Recreate the disposable environment so an older /tmp interpreter is replaced,
# even when it has the same Python version. Database/config/report files stay put.
"$AIVI_UV" venv --clear --python "$AIVI_PYTHON" "$AIVI_ROOT/.venv"
if [ "$AIVI_DEV" -eq 1 ]; then
    "$AIVI_UV" sync --frozen --python "$AIVI_PYTHON" --extra dev
else
    "$AIVI_UV" sync --frozen --python "$AIVI_PYTHON" --no-dev
fi
"$AIVI_ROOT/scripts/aivi" init-db
echo
echo "macOS setup complete. Start the dashboard with:"
echo "  ./scripts/aivi dashboard"
echo "Or double-click Start Dashboard.command in Finder."
