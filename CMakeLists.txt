cmake_minimum_required(VERSION 3.15)
project(ASM2HEX)

# Set C++ standard based on c_cpp_properties.json
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_OSX_DEPLOYMENT_TARGET 12.3)

# Options for static linking
option(BUILD_SHARED_LIBS "Build using shared libraries" OFF)

# Global defines from c_cpp_properties.json
if(APPLE)
    # Set wxWidgets paths explicitly for macOS
    set(wxWidgets_CONFIG_EXECUTABLE "${CMAKE_SOURCE_DIR}/dep/mac/mac_lib/bin/wx-config")
    set(wxWidgets_CONFIG_OPTIONS --prefix="${CMAKE_SOURCE_DIR}/dep/mac/mac_lib" --static=yes)
    
    # wxWidgets specific definitions for macOS
    add_definitions(
        -D__WXOSX_COCOA__ 
        -D_FILE_OFFSET_BITS=64
        -DWX_PRECOMP
        -D__ASSERT_MACROS_DEFINE_VERSIONS_WITHOUT_UNDERSCORES=1
    )
    
    # Include directories for wxWidgets
    include_directories(
        ${CMAKE_SOURCE_DIR}/dep/mac/mac_lib/lib/wx/include/osx_cocoa-unicode-static-3.2
        ${CMAKE_SOURCE_DIR}/dep/mac/include
        ${CMAKE_SOURCE_DIR}/src/cstool
        ${CMAKE_SOURCE_DIR}/dep/keystone/include
        ${CMAKE_SOURCE_DIR}/dep/capstone/include
    )
    
elseif(WIN32)
    set(wxWidgets_ROOT_DIR "${CMAKE_SOURCE_DIR}/dep/win")
    set(wxWidgets_CONFIGURATION mswu)
    add_definitions(-D_WINDOWS -D_UNICODE -D__WXMSW__ -DNDEBUG -DNOPCH -DwxUSE_UNICODE -WIN32)

    # Include directories for wxWidgets
    include_directories(
        ${CMAKE_SOURCE_DIR}/src/cstool
        ${CMAKE_SOURCE_DIR}/dep/win/lib/gcc_lib/mswu
        ${CMAKE_SOURCE_DIR}/dep/win/include
        ${CMAKE_SOURCE_DIR}/dep/keystone/include
        ${CMAKE_SOURCE_DIR}/dep/capstone/include
    )
else() # Linux
    set(wxWidgets_ROOT_DIR "${CMAKE_SOURCE_DIR}/dep/linux/linux_lib")
    set(wxWidgets_CONFIGURATION gtk3u)
    add_definitions(-D__WXGTK__ -D_FILE_OFFSET_BITS=64 -DWX_PRECOMP)

    # Include directories for wxWidgets
    include_directories(
        ${CMAKE_SOURCE_DIR}/dep/linux/linux_lib/lib/wx/include/gtk3-unicode-static-3.2
        ${CMAKE_SOURCE_DIR}/dep/linux/include
        /usr/include/gtk-3.0
        /usr/include/at-spi2-atk/2.0
        /usr/include/at-spi-2.0
        /usr/include/dbus-1.0
        /usr/lib/x86_64-linux-gnu/dbus-1.0/include
        /usr/include/gio-unix-2.0
        /usr/include/cairo
        /usr/include/pango-1.0
        /usr/include/fribidi
        /usr/include/harfbuzz
        /usr/include/atk-1.0
        /usr/include/pixman-1
        /usr/include/uuid
        /usr/include/freetype2
        /usr/include/libpng16
        /usr/include/gdk-pixbuf-2.0
        /usr/include/libmount
        /usr/include/blkid
        /usr/include/glib-2.0
        /usr/lib/x86_64-linux-gnu/glib-2.0/include
        /usr/include/gtk-3.0/unix-print
    )

endif()

# Add source files (from tasks.json Compile section)
file(GLOB_RECURSE SOURCES 
    "${CMAKE_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_SOURCE_DIR}/src/cstool/*.cpp"
    "${CMAKE_SOURCE_DIR}/src/cstool/*.c"
)

# Create executable
add_executable(${PROJECT_NAME} ${SOURCES})

# Platform specific settings from tasks.json
if(APPLE)

    # Find required packages
    find_package(TIFF REQUIRED)
    find_package(JPEG REQUIRED)
    find_package(PNG REQUIRED)
    find_package(ZLIB REQUIRED)
    
    # Directly specify wxWidgets libraries for macOS
    set(WX_LIBS
        "${CMAKE_SOURCE_DIR}/dep/mac/mac_lib/lib/libwx_osx_cocoau_core-3.2.a"
        "${CMAKE_SOURCE_DIR}/dep/mac/mac_lib/lib/libwx_osx_cocoau_stc-3.2.a"
        "${CMAKE_SOURCE_DIR}/dep/mac/mac_lib/lib/libwxscintilla-3.2.a"
        "${CMAKE_SOURCE_DIR}/dep/mac/mac_lib/lib/libwx_baseu-3.2.a"
    )

    # Compiler flags from tasks.json
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} \
        -isysroot ${CMAKE_OSX_SYSROOT} \
        -mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}"
    )
    
    # Link libraries from tasks.json
    target_link_libraries(${PROJECT_NAME} PRIVATE
        # Framework libraries
        "-framework IOKit"
        "-framework Carbon"
        "-framework Cocoa"
        "-framework AudioToolbox"
        "-framework System"
        "-framework OpenGL"
        "-framework WebKit"
        "-framework Security"
        "-framework QuartzCore"
        
        # Static libraries from wxWidgets
         ${WX_LIBS}
        
        # Additional libraries
        keystone
        capstone
        ${TIFF_LIBRARIES}
        ${JPEG_LIBRARIES}
        ${PNG_LIBRARIES}
        ${ZLIB_LIBRARIES}
        pcre2-32
        mspack
        pthread
        iconv
        lzma
    )

    # Link directories
    target_link_directories(${PROJECT_NAME} PRIVATE
        "${CMAKE_SOURCE_DIR}/dep/mac/mac_lib/lib"
        "${CMAKE_SOURCE_DIR}/dep/lib/osx"
        "/opt/homebrew/lib"
        "/usr/local/lib"
    )
elseif(WIN32)
    # Link flags and libraries from tasks.json
    target_link_libraries(${PROJECT_NAME} PRIVATE
        wxmsw32u_core
        wxbase32u
        wxpng
        comdlg32
        gdi32
        comctl32
        ole32
        oleaut32
        dmoguids
        uuid
        winspool
        z
        wxregexu
        wxzlib
        uxtheme
        oleacc
        shlwapi
        version
        keystone
        capstone
        wxjpeg
        wxpng
    )
    
    # Link directories
    target_link_directories(${PROJECT_NAME} PRIVATE
        "${CMAKE_SOURCE_DIR}/dep/win/lib/gcc_lib"
        "${CMAKE_SOURCE_DIR}/dep/lib/win"
    )
    
    target_compile_options(${PROJECT_NAME} PRIVATE
        -mwindows
        -static
    )
else() # Linux
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(GTK3 REQUIRED gtk+-3.0)
    
    target_include_directories(${PROJECT_NAME} PRIVATE 
        ${GTK3_INCLUDE_DIRS}
        ${CMAKE_SOURCE_DIR}/dep/linux/linux_lib/lib/wx/include/gtk3-unicode-static-3.2
        ${CMAKE_SOURCE_DIR}/dep/linux/include
    )
    # Link libraries from tasks.json
    target_link_libraries(${PROJECT_NAME} PRIVATE
        keystone
        capstone
        pthread
        ${GTK3_LIBRARIES}
        tiff
        jpeg
        xkbcommon
        gtk-3
        gdk-3
        pangocairo-1.0
        pango-1.0
        harfbuzz
        atk-1.0
        cairo-gobject
        cairo
        gdk_pixbuf-2.0
        gio-2.0
        gobject-2.0
        gthread-2.0
        glib-2.0
        X11
        SM
        png
        z
        dl
        m
        Xtst
        pangoft2-1.0
        fontconfig
        freetype
    )
    
    # Link directories
    target_link_directories(${PROJECT_NAME} PRIVATE
        "${CMAKE_SOURCE_DIR}/dep/linux/linux_lib/lib"
        "${CMAKE_SOURCE_DIR}/dep/lib/linux"
    )
    
    target_compile_options(${PROJECT_NAME} PRIVATE
        -pthread
        -fno-strict-aliasing
    )
endif()

# Set output directory (from tasks.json)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/out)

# Debug configurations from launch.json
set(CMAKE_BUILD_TYPE Debug)