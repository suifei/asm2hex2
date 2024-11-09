WINDOWS MINGWIN32-G++


CAPSTONE COMPILE
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DLLVM_TARGETS_TO_BUILD="AArch64;ARM;Hexagon;Mips;PowerPC;Sparc;SystemZ;X86" ..
ninja


KEYSTONE COMPILE
mkdir build && cd build
cmake -G "MinGW Makefiles" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DLLVM_TARGETS_TO_BUILD="all" \
    -DKEYSTONE_BUILD_STATIC_RUNTIME=ON \
    -DCMAKE_C_COMPILER=gcc \
    -DCMAKE_CXX_COMPILER=g++ \
    -DCMAKE_MAKE_PROGRAM=mingw32-make \
    -DCMAKE_SYSTEM_NAME=Windows \
    -DBUILD_LIBS_ONLY=ON \
    ..

mingw32-make