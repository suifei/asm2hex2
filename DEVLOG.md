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