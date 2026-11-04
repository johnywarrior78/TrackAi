#!/bin/bash
set -euo pipefail
AIVI_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
cd "$AIVI_ROOT"
if [ ! -x "$AIVI_ROOT/.venv/bin/python" ]; then
    "$AIVI_ROOT/scripts/setup_macos.sh"
fi
"$AIVI_ROOT/scripts/aivi" init-db
exec "$AIVI_ROOT/scripts/aivi" dashboard
