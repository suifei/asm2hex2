# ASM2HEX2 v1.0.3 发布说明

## 安全 / 防误报

部分 Windows Defender / SmartScreen 版本会对 **未代码签名** 的 MinGW 静态链接程序给出机器学习启发式告警，例如：

- `Trojan:Win32/Sabsik.FL.A!ml`

这是 **误报（False Positive）**，不是程序被植入木马。本仓库源码公开，Windows 构建仅静态链接 wxWidgets / Keystone / Capstone 与 MinGW 运行库，不包含网络后门或加密矿工逻辑。

### 本版本针对误报的构建改进

1. 嵌入 **VERSIONINFO**（产品名、作者、版本、项目 URL）
2. 嵌入 **application manifest**（asInvoker、常见控件、DPI）
3. **取消全量 `-s` strip**，仅 `--strip-debug`（全量剥离容易触发 Sabsik 类 ML 规则）
4. 编译优化由 `-Os` 调整为 `-O2`（更接近常规应用布局）

仍为 **静态链接** MinGW 运行库：不依赖 `libgcc` / `libstdc++` / `libwinpthread` DLL。

### 若仍被拦截

1. 到 [Microsoft Security Intelligence 误报提交](https://www.microsoft.com/en-us/wdsi/filesubmission) 选择 *Software developer*，上传 `ASM2HEX-win64.exe` 并注明 open-source GUI 工具与仓库地址。
2. 临时允许：Windows 安全中心 → 保护历史记录 → 允许；或添加文件夹排除（仅当你信任该来源）。
3. 优先从本 GitHub Release 下载，核对文件大小/发布说明。
4. 长期方案：使用 Authenticode **代码签名证书** 签名发布包（最有效降低 SmartScreen）。

## 下载

**Windows 仅提供 ZIP**（不解压不直接提供 `.exe` 下载，降低浏览器/SmartScreen 对裸 exe 的拦截）：

| 平台 | 文件 | 说明 |
|------|------|------|
| Windows x64 | **`ASM2HEX-win64.zip`** | 解压后得到 `ASM2HEX.exe` |
| Linux x64 | `ASM2HEX-linux-x64.tar.xz` | 解压后运行 `ASM2HEX` |
| macOS | `ASM2HEX-macos-arm64.tar.xz` | 解压后运行 `ASM2HEX`（若有） |

```text
# Windows
展开 ASM2HEX-win64.zip → 运行 ASM2HEX.exe
```

## 变更

- `src/win/asm2hex.rc` + `asm2hex.manifest`：版本与清单资源
- CMake Windows：链接资源文件；去掉全量 `-s`；静态运行库保留

## 版本

- 上一版本：v1.0.2
- 本版本：v1.0.3（Windows 误报缓解补丁）
