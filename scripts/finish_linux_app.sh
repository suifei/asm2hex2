#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

if [[ ! -f build-linux/build.ninja ]]; then
  cmake -S . -B build-linux -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF
fi

cmake --build build-linux -j"$(nproc 2>/dev/null || echo 8)"

BIN=""
if [[ -f out/ASM2HEX ]]; then
  BIN=out/ASM2HEX
elif [[ -f build-linux/ASM2HEX ]]; then
  cp -f build-linux/ASM2HEX out/ASM2HEX
  BIN=out/ASM2HEX
else
  echo "NOBIN" >&2
  find build-linux -name 'ASM2HEX*' -type f || true
  exit 1
fi

mkdir -p dist
cp -f "$BIN" dist/ASM2HEX-linux-x64
chmod +x dist/ASM2HEX-linux-x64
strip -s dist/ASM2HEX-linux-x64 2>/dev/null || true
ls -lh dist/ASM2HEX-linux-x64
file dist/ASM2HEX-linux-x64 || true
echo "=== ldd ==="
ldd dist/ASM2HEX-linux-x64 || true
echo "=== libstdc check ==="
if ldd dist/ASM2HEX-linux-x64 | grep -E 'libstdc\+\+|libgcc_s'; then
  echo "WARN: dynamic libgcc/libstdc++ still present" >&2
else
  echo "NO_LIBSTDCPP_DYN_OK"
fi
echo "OK"
