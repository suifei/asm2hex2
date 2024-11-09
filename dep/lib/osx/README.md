## dependencies

- capstone-5.0.3
- keystone-0.9.2.zip
- wxWidgets-3.2.3.zip

## macos builder
### build libkeystone.a
```shell
mkdir build && cd build
CMAKE_OSX_DEPLOYMENT_TARGET=14.5 ../make-lib.sh  
```
### build capstone
```shell
mkdir build && cd build
cmake -DCMAKE_OSX_DEPLOYMENT_TARGET=14.5 ..
cmake --build . --config Release
```
### build wxwidgets
```shell
cd mac 
mkdir mac_lib && cd mac_lib

# 首先安装所有需要的依赖
brew install libjpeg libpng libtiff xz sdl12-compat libmspack
# 代理方式安装
# HTTP_PROXY=http://localhost:8080 HTTPS_PROXY=http://localhost:8080 brew install libjpeg libpng libtiff xz sdl12-compat libmspack

# 配置编译
../configure --disable-shared --enable-unicode --prefix="$(pwd)" --with-macosx-sdk=/Library/Developer/CommandLineTools/SDKs/MacOSX15.1.sdk --with-macosx-version-min=14.5 --with-osx_cocoa --enable-stl --with-libjpeg=sys --with-libpng=sys --with-libtiff=sys --with-regex=sys --with-liblzma=sys --with-zlib=sys --with-expat=sys --with-libmspack=sys --with-sdl CPPFLAGS="-I/opt/homebrew/include" LDFLAGS="-L/opt/homebrew/lib"

make -j$(sysctl -n hw.ncpu)
make install
``` 
intel mac
```shell
CPPFLAGS="-I/usr/local/include" \
LDFLAGS="-L/usr/local/lib"
```

```bash
# 访问 https://developer.apple.com/download/all/
# 下载对应版本的 "Command Line Tools for Xcode"
```