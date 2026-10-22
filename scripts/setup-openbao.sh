#!/usr/bin/env bash
set +x
set -euo pipefail
command -v python3 >/dev/null || { echo 'Install Python 3 to run this helper (no Python packages needed).' >&2; exit 1; }
exec python3 "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/setup_openbao.py"
