# ASM2HEX2 v1.0.1 发布说明

Patch release focused on Linux build fixes reported in open issues.

## 修复 (Fixes)

### [#2](https://github.com/suifei/asm2hex2/issues/2) Linux 下编译遇到的几个问题

按社区反馈与 diff 修复 `CMakeLists.txt` 的 Linux 分支（Windows / macOS 分支保持不变）：

1. **`src/cstool` 加入 include 路径** — 解决 cstool 头文件找不到的问题
2. **链接 wxWidgets 静态库** — 按依赖顺序链接 `stc` → `scintilla` → `adv` / `html` → `core` → `base`
3. **可选链接 gspell** — 通过 `pkg_check_modules(GSPELL gspell-1)`（非 REQUIRED），找到时链接 `${GSPELL_LIBRARIES}`
4. **链接 `Xxf86vm`** — 补齐 X11 相关符号

另外在 Linux include 路径中补齐 `dep/keystone/include` 与 `dep/capstone/include`，与 Windows/macOS 一致。

## 构建说明

### Windows

```bash
mkdir build && cd build
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

可执行文件：`out/ASM2HEX.exe` 或 `build/ASM2HEX.exe`（视 CMake 输出目录配置而定）。

### Linux

1. 按 `doc/linux.pdf` 准备静态 wxWidgets（`dep/linux/`）
2. 安装系统依赖（GTK3、X11 等）；如需拼写检查相关符号可安装 `libgspell-1-dev`
3. 配置并编译：

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

### 回归检查（CMake 结构）

```bash
python3 tests/test_cmake_linux_fixes.py
```

## 版本

- 上一版本：v1.0.0
- 本版本：v1.0.1（fix-only patch）

## 致谢

感谢在 [#2](https://github.com/suifei/asm2hex2/issues/2) 中提供复现与参考 diff 的报告者。
