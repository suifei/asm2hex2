#!/usr/bin/env bash
# Build static-as-possible Linux binary for ASM2HEX:
# - static wxWidgets, Keystone, Capstone, libgcc, libstdc++
# - shared GTK/X11 (normal for Linux GUI)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEP="${ROOT}/dep"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"
WX_VER="${WX_VER:-3.2.6}"
CAPSTONE_VER="${CAPSTONE_VER:-5.0.3}"
KEYSTONE_VER="${KEYSTONE_VER:-0.9.2}"
CACHE="${CACHE_DIR:-${ROOT}/.deps-cache}"
mkdir -p "${CACHE}" "${DEP}/lib/linux" "${ROOT}/out" "${ROOT}/dist"

echo "==> Root: ${ROOT}"
echo "==> Jobs: ${JOBS}"

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "missing command: $1" >&2; exit 1; }; }
need_cmd cmake
need_cmd g++
need_cmd make
need_cmd pkg-config
need_cmd curl
need_cmd tar

# --- Capstone static ---
build_capstone() {
  local out="${DEP}/lib/linux/libcapstone.a"
  if [[ -f "${out}" ]]; then
    echo "==> Capstone already present: ${out}"
    return 0
  fi
  local src="${CACHE}/capstone-${CAPSTONE_VER}"
  if [[ ! -d "${src}" ]]; then
    echo "==> Downloading Capstone ${CAPSTONE_VER}"
    curl -fsSL "https://github.com/capstone-engine/capstone/archive/refs/tags/${CAPSTONE_VER}.tar.gz" \
      | tar -xz -C "${CACHE}"
  fi
  rm -rf "${src}/build"
  cmake -S "${src}" -B "${src}/build" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DCAPSTONE_BUILD_SHARED=OFF \
    -DCAPSTONE_BUILD_STATIC=ON \
    -DCAPSTONE_BUILD_TESTS=OFF \
    -DCAPSTONE_BUILD_CSTOOL=OFF
  cmake --build "${src}/build" -j"${JOBS}"
  # Install archive to dep/lib/linux
  local lib
  lib="$(find "${src}/build" -name 'libcapstone.a' | head -n1)"
  cp -f "${lib}" "${out}"
  # Headers already expected under dep/capstone/include when vendored; copy if missing
  if [[ ! -f "${DEP}/capstone/include/capstone/capstone.h" ]]; then
    mkdir -p "${DEP}/capstone/include"
    cp -a "${src}/include/." "${DEP}/capstone/include/"
  fi
  echo "==> Capstone -> ${out}"
}

# --- Keystone static ---
build_keystone() {
  local out="${DEP}/lib/linux/libkeystone.a"
  if [[ -f "${out}" ]]; then
    echo "==> Keystone already present: ${out}"
    return 0
  fi
  local src="${CACHE}/keystone-${KEYSTONE_VER}"
  if [[ ! -d "${src}" ]]; then
    echo "==> Downloading Keystone ${KEYSTONE_VER}"
    # keystone tags are sometimes bare version
    if ! curl -fsSL "https://github.com/keystone-engine/keystone/archive/refs/tags/${KEYSTONE_VER}.tar.gz" \
      | tar -xz -C "${CACHE}"; then
      curl -fsSL "https://github.com/keystone-engine/keystone/archive/${KEYSTONE_VER}.tar.gz" \
        | tar -xz -C "${CACHE}"
    fi
    # normalize dir name
    if [[ ! -d "${src}" ]]; then
      local found
      found="$(find "${CACHE}" -maxdepth 1 -type d -name 'keystone*' | head -n1)"
      mv "${found}" "${src}"
    fi
  fi
  rm -rf "${src}/build"
  cmake -S "${src}" -B "${src}/build" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_LIBS_ONLY=ON \
    -DKEYSTONE_BUILD_STATIC_RUNTIME=ON \
    -DLLVM_TARGETS_TO_BUILD="all"
  cmake --build "${src}/build" -j"${JOBS}"
  local lib
  lib="$(find "${src}/build" -name 'libkeystone.a' | head -n1)"
  cp -f "${lib}" "${out}"
  if [[ ! -f "${DEP}/keystone/include/keystone/keystone.h" ]]; then
    mkdir -p "${DEP}/keystone/include"
    cp -a "${src}/include/." "${DEP}/keystone/include/"
  fi
  echo "==> Keystone -> ${out}"
}

# --- wxWidgets static ---
build_wx() {
  local marker="${DEP}/linux/linux_lib/lib/libwx_gtk3u_core-3.2.a"
  if [[ -f "${marker}" ]]; then
    echo "==> wxWidgets already present: ${marker}"
    return 0
  fi
  # dep/linux may be a placeholder file in the repo — replace with a directory
  if [[ -f "${DEP}/linux" ]]; then
    rm -f "${DEP}/linux"
  fi
  mkdir -p "${DEP}/linux"
  local src="${CACHE}/wxWidgets-${WX_VER}"
  if [[ ! -d "${src}" ]]; then
    echo "==> Downloading wxWidgets ${WX_VER}"
    curl -fsSL "https://github.com/wxWidgets/wxWidgets/releases/download/v${WX_VER}/wxWidgets-${WX_VER}.tar.bz2" \
      | tar -xj -C "${CACHE}"
  fi
  local prefix="${DEP}/linux/linux_lib"
  # Build in a separate directory from the install prefix to avoid
  # "install: same file" errors when prefix == builddir.
  local builddir="${CACHE}/wx-build-${WX_VER}"
  rm -rf "${prefix}" "${builddir}"
  mkdir -p "${prefix}" "${builddir}"
  pushd "${builddir}" >/dev/null
  "${src}/configure" \
    --with-gtk=3 \
    --disable-shared \
    --enable-unicode \
    --enable-stl \
    --disable-debug \
    --disable-mediactrl \
    --disable-webview \
    --prefix="${prefix}" \
    CXXFLAGS="-O2 -fPIC" \
    CFLAGS="-O2 -fPIC"
  make -j"${JOBS}"
  make install
  popd >/dev/null
  # wx install puts public headers under include/wx-3.2/wx/...
  # CMake expects dep/linux/include/wx/wx.h
  rm -f "${DEP}/linux/include"
  if [[ -d "${prefix}/include/wx-3.2" ]]; then
    ln -sfn "linux_lib/include/wx-3.2" "${DEP}/linux/include"
  elif [[ -d "${prefix}/include/wx" ]]; then
    ln -sfn "linux_lib/include" "${DEP}/linux/include"
  else
    echo "ERROR: wx public headers not found under ${prefix}/include" >&2
    find "${prefix}/include" -maxdepth 3 -type d | head -40 || true
    exit 1
  fi
  # Sanity: core static archive + headers must exist
  if [[ ! -f "${marker}" ]]; then
    echo "ERROR: wx core static library missing after install: ${marker}" >&2
    ls -la "${prefix}/lib" || true
    exit 1
  fi
  if [[ ! -f "${DEP}/linux/include/wx/wx.h" ]]; then
    echo "ERROR: wx/wx.h missing at ${DEP}/linux/include/wx/wx.h" >&2
    ls -la "${DEP}/linux/include" || true
    exit 1
  fi
  echo "==> wxWidgets -> ${prefix}"
}

build_capstone
build_keystone
build_wx

# --- App ---
echo "==> Configuring ASM2HEX"
rm -rf "${ROOT}/build-linux"
cmake -S "${ROOT}" -B "${ROOT}/build-linux" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF
cmake --build "${ROOT}/build-linux" -j"${JOBS}"

BIN=""
if [[ -f "${ROOT}/out/ASM2HEX" ]]; then
  BIN="${ROOT}/out/ASM2HEX"
elif [[ -f "${ROOT}/build-linux/ASM2HEX" ]]; then
  BIN="${ROOT}/build-linux/ASM2HEX"
  cp -f "${BIN}" "${ROOT}/out/ASM2HEX"
  BIN="${ROOT}/out/ASM2HEX"
else
  echo "ERROR: binary not found" >&2
  find "${ROOT}/build-linux" -type f -name 'ASM2HEX*' || true
  exit 1
fi

chmod +x "${BIN}"
strip -s "${BIN}" 2>/dev/null || true
cp -f "${BIN}" "${ROOT}/dist/ASM2HEX-linux-x64"
echo "==> Built: ${ROOT}/dist/ASM2HEX-linux-x64"
ls -lh "${ROOT}/dist/ASM2HEX-linux-x64"
file "${ROOT}/dist/ASM2HEX-linux-x64" || true
ldd "${ROOT}/dist/ASM2HEX-linux-x64" || true
echo "OK"
