#!/bin/bash
# Compatible with the Bash 3.2 supplied by macOS. Installs only in this project.
set -euo pipefail
umask 077

AIVI_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
AIVI_DEV=0
AIVI_SKIP_BACKFILL=0
for argument in "$@"; do
    case "$argument" in
        --dev) AIVI_DEV=1 ;;
        --skip-backfill) AIVI_SKIP_BACKFILL=1 ;;
        --help|-h)
            echo "Usage: $0 [--dev] [--skip-backfill]"
            echo "Install native dependencies and populate historical vulnerabilities on first setup."
            exit 0 ;;
        *) echo "Unknown option: $argument" >&2; exit 2 ;;
    esac
done
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

. "$AIVI_ROOT/scripts/setup_common.sh"
echo
echo "macOS setup complete. Start the dashboard with:"
echo "  ./scripts/aivi dashboard"
echo "Or double-click Start Dashboard.command in Finder."
