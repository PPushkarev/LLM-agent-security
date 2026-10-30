#!/usr/bin/env bash
# Explicit local model installation, outside the harness's writable workspace.
set -euo pipefail
source_dir=$(cd "$(dirname "$0")/../services/injection" && pwd)
runtime_dir=${GUARD_INJECTION_HOME:-"$HOME/.guard/injection"}
mkdir -p "$runtime_dir"
chmod 700 "$runtime_dir"
"${PYTHON:-python3}" -m venv "$runtime_dir/venv"
"$runtime_dir/venv/bin/python" -m pip install -r "$source_dir/requirements.txt"
"$runtime_dir/venv/bin/python" "$source_dir/download.py" --model-dir "$runtime_dir/model"
mkdir -p "$runtime_dir/app"
cp "$source_dir/server.py" "$source_dir/model_spec.py" "$runtime_dir/app/"
"$runtime_dir/venv/bin/python" - "$runtime_dir/token" <<'PY'
import os
import secrets
import sys
path = sys.argv[1]
try:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
except FileExistsError:
    pass
else:
    with os.fdopen(descriptor, 'w') as stream:
        stream.write(secrets.token_urlsafe(32) + '\n')
PY
printf 'Classifier installed in %s\n' "$runtime_dir"
printf 'Start: %s/venv/bin/python %s/app/server.py --model-dir %s/model --token-file %s/token\n' "$runtime_dir" "$runtime_dir" "$runtime_dir" "$runtime_dir"
