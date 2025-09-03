#!/usr/bin/env bash
# wxwidgets_mingw64_setup.sh
# 自动下载/检测 MinGW64，配置环境变量，下载并编译 wxWidgets（静态库，64位，release）
# 适用于 Windows + MSYS2/MinGW64 bash 环境


set -e

# 语言选择，默认 english，可选 chinese（简体中文）
LANGUAGE="english"
if [ -n "$1" ]; then
    if [ "$1" = "chinese" ] || [ "$1" = "zh" ] || [ "$1" = "zh-cn" ]; then
        LANGUAGE="chinese"
    fi
fi

# 多语言提示函数
function msg() {
    if [ "$LANGUAGE" = "chinese" ]; then
        case $1 in
            mingw_found) echo "[信息] 检测到 MinGW64 已安装于 $MINGW_BIN";;
            mingw_notfound) echo "[信息] 未检测到 MinGW64，开始下载安装...";;
            mingw_done) echo "[信息] MinGW64 安装完成。";;
            path_set) echo "[信息] 已将 $MINGW_BIN 添加到 PATH";;
            wx_downloading) echo "[信息] 下载 wxWidgets $WX_VERSION...";;
            wx_unzip) echo "[信息] wxWidgets 解压完成。";;
            wx_exists) echo "[信息] wxWidgets 已存在，无需下载。";;
            wx_building) echo "[信息] 开始编译 wxWidgets...";;
            wx_success) echo "[成功] wxWidgets 编译完成，库文件位于 $WX_DIR/lib/gcc_lib";;
            wx_fail) echo "[错误] wxWidgets 编译失败，请检查日志。";;
        esac
    else
        case $1 in
            mingw_found) echo "[INFO] MinGW64 found at $MINGW_BIN";;
            mingw_notfound) echo "[INFO] MinGW64 not found, start downloading...";;
            mingw_done) echo "[INFO] MinGW64 installation completed.";;
            path_set) echo "[INFO] $MINGW_BIN added to PATH";;
            wx_downloading) echo "[INFO] Downloading wxWidgets $WX_VERSION...";;
            wx_unzip) echo "[INFO] wxWidgets extracted.";;
            wx_exists) echo "[INFO] wxWidgets already exists, skip download.";;
            wx_building) echo "[INFO] Start building wxWidgets...";;
            wx_success) echo "[SUCCESS] wxWidgets build finished, libraries at $WX_DIR/lib/gcc_lib";;
            wx_fail) echo "[ERROR] wxWidgets build failed, please check log.";;
        esac
    fi
}

# 配置参数
MINGW_VERSION="8.1.0"
MINGW_URL="https://github.com/niXman/mingw-builds-binaries/releases/download/8.1.0/x86_64-8.1.0-release-posix-seh-rt_v6-rev0.7z"
MINGW_DIR="/c/mingw-w64"
MINGW_BIN="$MINGW_DIR/mingw64/bin"
WX_VERSION="3.2.3"
WX_URL="https://github.com/wxWidgets/wxWidgets/releases/download/v$WX_VERSION/wxWidgets-$WX_VERSION.zip"
WX_DIR="$(pwd)/win"
WX_BUILD_DIR="$WX_DIR/build/msw"



# 检查 MinGW64 是否已安装（通过检测 g++ 和 mingw32-make.exe 是否在 PATH 中）
if command -v g++ >/dev/null 2>&1 && command -v mingw32-make.exe >/dev/null 2>&1; then
    msg mingw_found
    MINGW_BIN=$(dirname $(command -v g++))
else
    msg mingw_notfound
    # 默认下载到 /c/mingw-w64
    cd /c && \
    curl -L -o mingw-w64.7z "$MINGW_URL" && \
    7z x mingw-w64.7z && \
    rm mingw-w64.7z
    msg mingw_done
    MINGW_BIN="$MINGW_DIR/mingw64/bin"
    export PATH="$MINGW_BIN:$PATH"
    msg path_set
fi

# 若未设置 PATH，则补充设置
if ! echo "$PATH" | grep -q "$MINGW_BIN"; then
    export PATH="$MINGW_BIN:$PATH"
    msg path_set
fi

# 下载 wxWidgets
cd "$(dirname "$0")"
if [ ! -d "$WX_DIR" ]; then
    mkdir -p "$WX_DIR"
fi
cd "$WX_DIR"
if [ ! -d "wxWidgets-$WX_VERSION" ]; then
    msg wx_downloading
    curl -L -o wxWidgets.zip "$WX_URL"
    unzip wxWidgets.zip
    rm wxWidgets.zip
    mv wxWidgets-$WX_VERSION/* .
    rmdir wxWidgets-$WX_VERSION
    msg wx_unzip
else
    msg wx_exists
fi

# 编译 wxWidgets
cd "$WX_BUILD_DIR"
msg wx_building
mingw32-make.exe -f makefile.gcc SHARED=0 UNICODE=1 BUILD=release

if [ $? -eq 0 ]; then
    msg wx_success
else
    msg wx_fail
    exit 1
fi
