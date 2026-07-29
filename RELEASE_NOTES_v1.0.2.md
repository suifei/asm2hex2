# ASM2HEX2 v1.0.2 发布说明

Multi-platform **static-linked** prebuilt binaries.

## 亮点

- **Windows x64**：全静态 MinGW 链接（无 `libgcc` / `libstdc++` / `libwinpthread` DLL 依赖），仅依赖系统 DLL
- **Linux x64**：静态链接 wxWidgets、Keystone、Capstone 与 libgcc/libstdc++；GTK/X11 仍为系统共享库（Linux GUI 常规方式）
- **macOS arm64**：静态链接 wxWidgets + 引擎；系统 Framework 保持动态（Cocoa 常规方式）
- 保留 v1.0.1 的 Linux CMake 修复（#2）

## 下载

| 平台 | 文件 |
|------|------|
| Windows x64 | `ASM2HEX-win64.exe` 或 `ASM2HEX-win64.7z` |
| Linux x64 | `ASM2HEX-linux-x64` 或 `ASM2HEX-linux-x64.tar.xz` |
| macOS Apple Silicon | `ASM2HEX-macos-arm64` 或 `ASM2HEX-macos-arm64.tar.xz` |

## 使用

- **Windows**：直接运行 `ASM2HEX-win64.exe`（Win7+）
- **Linux**：`chmod +x ASM2HEX-linux-x64 && ./ASM2HEX-linux-x64`（需 GTK3 运行库）
- **macOS**：`chmod +x ASM2HEX-macos-arm64 && ./ASM2HEX-macos-arm64`（首次可能需在「隐私与安全性」中允许）

## 从源码静态构建

```bash
# Windows (MinGW + Ninja)
powershell -File scripts/build_win_static.ps1

# Linux
./scripts/build_linux_static.sh
```

GitHub Actions workflow：`.github/workflows/release-binaries.yml`（Windows / Linux / macOS）。

## 变更摘要

- CMake：`-static` / `-static-libgcc` / `-static-libstdc++` 放到 **link** 选项（此前误放在 compile 导致仍依赖 MinGW DLL）
- CMake：修复 `CMAKE_RUNTIME_OUTPUT_DIRECTORY` 顺序，产物输出到 `out/`
- 新增跨平台静态构建脚本与 Release CI
- Linux 优先使用 `dep/lib/linux/*.a` 静态引擎库

## 版本

- 上一版本：v1.0.1
- 本版本：v1.0.2
