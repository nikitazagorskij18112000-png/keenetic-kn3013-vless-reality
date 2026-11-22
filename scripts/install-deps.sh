#!/usr/bin/env bash
set -euo pipefail
if [[ $(id -u) != 0 ]]; then
  echo 'Run: sudo bash scripts/install-deps.sh' >&2
  exit 1
fi
apt-get update
apt-get install -y --no-install-recommends \
  attr bc bsdextrautils bison build-essential ca-certificates cpio curl file flex \
  gawk gettext git gperf jq libhtml-parser-perl libjson-perl libncurses-dev \
  libssl-dev libxml-libxml-perl lzip pkgconf protobuf-c-compiler python3 \
  python3-venv qemu-user rsync subversion texinfo unzip wget xz-utils zlib1g-dev
echo 'Dependencies installed. Run the builder WITHOUT sudo.'
