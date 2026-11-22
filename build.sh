#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
if [[ $(uname -s) != Linux || $(id -u) == 0 ]]; then
  echo 'Run as a regular user in Ubuntu 24.04 / WSL 2, not as root.' >&2
  exit 1
fi
kit_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
kit_venv="${XDG_CACHE_HOME:-$HOME/.cache}/kn3013-kit/venv"
if [[ ! -x "$kit_venv/bin/python" ]]; then
  python3 -m venv "$kit_venv"
fi
"$kit_venv/bin/python" -m pip --disable-pip-version-check install --quiet -r "$kit_dir/requirements.txt"
exec "$kit_venv/bin/python" "$kit_dir/build.py" "$@"
