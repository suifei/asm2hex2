# ASM2HEX2 v1.0.0 发布说明

## 新特性
- 支持 Windows (MinGW64)、macOS、Linux 多平台编译与运行
- 集成 wxWidgets 跨平台 GUI，界面友好
- 支持汇编代码与十六进制互转，适配多种架构
- 内置 Capstone/Keystone 引擎，支持反汇编与汇编
- 支持批量转换、文件拖拽、剪贴板操作
- 丰富的错误提示与日志输出
- 提供自动化脚本一键配置 MinGW64 和 wxWidgets 环境（Windows）
- CMake 构建系统，支持体积优化编译参数

## 优化与修复
- Windows 版本默认静态链接，减小依赖
- 优化编译参数，减小可执行文件体积
- 兼容新版 wxWidgets 3.2.3
- 修复部分平台下路径和环境变量问题

## 使用说明
1. 按照 dep 目录下脚本/文档配置依赖环境
2. 使用 CMake 进行跨平台编译
3. 运行 out/ASM2HEX.exe（或对应平台可执行文件）

## 致谢
感谢 wxWidgets、Capstone、Keystone 等开源项目。

---
如有问题请查阅 README 或提交 issue。
