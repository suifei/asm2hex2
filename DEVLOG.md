## Windows 资源文件
在 MS Windows 下编译 wxWidgets 应用程序至少需要一个额外的文件：资源文件。

必须在 Windows 资源文件（扩展名 RC）中定义的最少语句是以下语句：
```
#include "wx/msw/wx.rc"
```
其中包括基本的内部 wxWidgets 定义。资源脚本还可能包含对图标、光标等的引用，例如：
```
wxicon icon wx.ico
```
然后，在创建框架图标时，可以按名称引用该图标。请参阅 Microsoft Windows SDK 文档。

注意
在任何 ICON 语句后包括 “wx.rc”，以便在可执行文件中搜索图标的程序（如 Program Manager）首先找到应用程序图标。


## CMAKE Xcode
安装 Xcode Command Line Tools 或者 CMake 找不到编译器解决步骤：

1. 首先，确保你已经安装了 Xcode（从 App Store 安装）

2. 安装 Command Line Tools：
```bash
xcode-select --install
```

3. 确认 Xcode 命令行工具的路径：
```bash
xcode-select -p
```
应该显示类似：/Applications/Xcode.app/Contents/Developer

4. 如果上面的路径不对，可以重置：
```bash
sudo xcode-select --reset
```

5. 接着清理 CMake 缓存并重新运行：
```bash
cd build-xcode
rm -rf *
cmake -G "Xcode" -DCMAKE_OSX_DEPLOYMENT_TARGET=12.3 ..
```

如果还有问题，可以试试明确指定编译器：

```bash
cmake -G "Xcode" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=12.3 \
    -DCMAKE_C_COMPILER=/usr/bin/clang \
    -DCMAKE_CXX_COMPILER=/usr/bin/clang++ \
    ..
```

你也可以查看下编译器是否正确安装：
```bash
clang --version
clang++ --version
```

如果上述命令显示编译器版本信息，说明编译器已正确安装。如果命令不存在，则需要重新安装 Xcode Command Line Tools。

请告诉我执行结果，这样我可以帮你进一步解决问题。
Macos
```shell
cmake -G "Xcode" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=12.3 \
    -DCMAKE_C_COMPILER=/usr/bin/clang \
    -DCMAKE_CXX_COMPILER=/usr/bin/clang++ \
    ..
```