#!/bin/bash
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
if [ "$(uname -s)" != Linux ]; then
    echo "Use setup_macos.sh on macOS." >&2
    exit 1
fi
case "$(uname -m)" in
    x86_64|aarch64|arm64) ;;
    *) echo "Supported Linux architectures: x86_64 and aarch64." >&2; exit 1 ;;
esac
if ! AIVI_LIBC="$(getconf GNU_LIBC_VERSION 2>/dev/null)"; then
    echo "Use a glibc-based distribution (Ubuntu, Debian, Fedora or RHEL); musl/Alpine native installation is unsupported." >&2
    exit 1
fi
AIVI_GLIBC_MAJOR="$(echo "$AIVI_LIBC" | cut -d' ' -f2 | cut -d. -f1)"
AIVI_GLIBC_MINOR="$(echo "$AIVI_LIBC" | cut -d' ' -f2 | cut -d. -f2)"
if [ "$AIVI_GLIBC_MAJOR" -lt 2 ] || { [ "$AIVI_GLIBC_MAJOR" -eq 2 ] && [ "$AIVI_GLIBC_MINOR" -lt 28 ]; }; then
    echo "The locked native dependencies require glibc 2.28 or newer." >&2
    exit 1
fi
. "$AIVI_ROOT/scripts/setup_common.sh"
echo "Linux setup complete. Start the dashboard: ./scripts/aivi dashboard"
