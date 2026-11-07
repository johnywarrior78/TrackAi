# Shared by the native macOS/Linux entry points; source this file.
cd "$AIVI_ROOT"
if [ -x "$AIVI_ROOT/.bootstrap/bin/uv" ]; then
    AIVI_UV="$AIVI_ROOT/.bootstrap/bin/uv"
elif command -v uv >/dev/null 2>&1; then
    AIVI_UV="$(command -v uv)"
else
    AIVI_BOOTSTRAP_PYTHON="${AIVI_BOOTSTRAP_PYTHON:-python3}"
    if ! command -v "$AIVI_BOOTSTRAP_PYTHON" >/dev/null 2>&1; then
        echo "Install uv or Python 3 with venv/pip, then rerun this script." >&2
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
if [ "$AIVI_SKIP_BACKFILL" -eq 1 ]; then
    "$AIVI_ROOT/scripts/aivi" init-db
else
    "$AIVI_ROOT/scripts/aivi" initialize
fi
