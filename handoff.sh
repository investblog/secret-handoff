#!/usr/bin/env bash
# secret-handoff — the launcher: resolves Python the way the hooks do (AGENTS_PYTHON, python3,
# python, py -3) and runs handoff.py beside it. Without Python it fails (a handoff never fails open).
dir="$(cd "$(dirname "$0")" && pwd)"
if [ -n "${AGENTS_PYTHON:-}" ]; then exec "$AGENTS_PYTHON" "$dir/handoff.py" "$@"; fi
if command -v python3 >/dev/null 2>&1; then exec python3 "$dir/handoff.py" "$@"; fi
if command -v python >/dev/null 2>&1; then exec python "$dir/handoff.py" "$@"; fi
if command -v py >/dev/null 2>&1; then exec py -3 "$dir/handoff.py" "$@"; fi
echo "handoff: no Python (AGENTS_PYTHON, python3, python, py -3)" >&2
exit 1
