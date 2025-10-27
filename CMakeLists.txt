cmake_minimum_required(VERSION 3.20)
project(NeutralinoJS LANGUAGES C CXX)
set(NEU_VERSION "6.3.0")
set(NEU_CXX_STANDARD 17)

execute_process(
  COMMAND git rev-parse HEAD
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE NEU_COMMIT
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET
)

# =========================
# Source files
# =========================
file (GLOB SOURCES *.cpp)
file(GLOB_RECURSE RECURSIVE_SOURCES
  auth/*.cpp
  server/*.cpp
  api/*.cpp
  lib/tinyprocess/process.cpp
  lib/easylogging/easylogging++.cc
  lib/platformfolders/platform_folders.cpp
  lib/clip/clip.cpp
  lib/clip/image.cpp
  lib/infoware/src/**/*.cpp
  lib/efsw/src/efsw/*.cpp
)
list(APPEND SOURCES ${RECURSIVE_SOURCES})

if(WIN32)
  file(GLOB_RECURSE OS_SOURCES
    lib/tinyprocess/process_win.cpp
    lib/clip/clip_win.cpp
    lib/efsw/src/efsw/platform/win/*.cpp
    lib/postject/windows_dummy.res
  )
  list(APPEND SOURCES ${OS_SOURCES})
elseif(APPLE)
  file(GLOB_RECURSE OS_SOURCES
    lib/tinyprocess/process_unix.cpp
    lib/clip/clip_osx.mm
    lib/webview/macwindow.mm
    lib/efsw/src/efsw/platform/posix/*.cpp
  )
  list(APPEND SOURCES ${OS_SOURCES})
elseif(UNIX)
  file(GLOB_RECURSE OS_SOURCES
    lib/tinyprocess/process_unix.cpp
    lib/clip/clip_x11.cpp
    lib/efsw/src/efsw/platform/posix/*.cpp
  )
  list(APPEND SOURCES ${OS_SOURCES})
endif()
list(FILTER SOURCES EXCLUDE REGEX ".*/asio/src/.*")

# =========================
# Create executable or library
# =========================
add_executable(${PROJECT_NAME} ${SOURCES})
set(OUTPUT_NAME_STR "neutralino-${CMAKE_SYSTEM_NAME}_${CMAKE_SYSTEM_PROCESSOR}")
set_target_properties(${PROJECT_NAME} PROPERTIES 
  OUTPUT_NAME ${OUTPUT_NAME_STR}
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# =========================
# Compiler definitions
# =========================
target_compile_definitions(${PROJECT_NAME} PRIVATE 
  NEU_VERSION="${NEU_VERSION}"
  NEU_COMMIT="${NEU_COMMIT}"
  ELPP_NO_DEFAULT_LOG_FILE=1
  ASIO_STANDALONE
  INFOWARE_VERSION="0.6.0"
  INFOWARE_USE_X11
  CLIP_ENABLE_IMAGE
)

if(WIN32)
  target_compile_definitions(${PROJECT_NAME} PRIVATE 
    _WEBSOCKETPP_CPP11_STL_
    _HAS_STD_BYTE=0
    TRAY_WINAPI=1
    UNICODE
    _UNICODE
  )
elseif(APPLE)
  target_compile_definitions(${PROJECT_NAME} PRIVATE 
    WEBVIEW_COCOA=1
    TRAY_APPKIT=1
    MACOSX_DEPLOYMENT_TARGET=10.7
  )
elseif(UNIX)
  target_compile_definitions(${PROJECT_NAME} PRIVATE 
    HAVE_XCB_XLIB_H
    WEBVIEW_GTK=1
    TRAY_APPINDICATOR=1
    HAVE_PNG_H
  )
endif()

# =========================
# Include paths
# =========================
target_include_directories(${PROJECT_NAME} PUBLIC 
  ${PROJECT_SOURCE_DIR}
  ${PROJECT_SOURCE_DIR}/lib
  ${PROJECT_SOURCE_DIR}/lib/asio/include
  ${PROJECT_SOURCE_DIR}/lib/infoware/include
  ${PROJECT_SOURCE_DIR}/lib/efsw/include
  ${PROJECT_SOURCE_DIR}/lib/efsw/src
)
if(WIN32)
  target_include_directories(${PROJECT_NAME} PRIVATE 
    ${PROJECT_SOURCE_DIR}/lib/webview/windows
  )
endif()

# =========================
# Compiler options by platform
# =========================
if(WIN32)
    # Windows
    target_compile_options(${PROJECT_NAME} PRIVATE
      /utf-8
      /EHsc
      /Os
      /Gy 
      /OPT:REF 
      /OPT:ICF
    )
    
    target_link_libraries(${PROJECT_NAME} PRIVATE
      ${PROJECT_SOURCE_DIR}/lib/webview/windows/WebView2LoaderStatic.lib
      gdi32
      version
      Ole32
      OleAut32
      wbemuuid
      ntdll
      dwmapi
    )
elseif(APPLE)
    # macOS
    find_library(WebKit_FRAMEWORK WebKit)
    find_library(COCOA_FRAMEWORK Cocoa)
    target_link_libraries(${PROJECT_NAME} PRIVATE
      ${WebKit_FRAMEWORK}
      ${COCOA_FRAMEWORK}
    )

    target_compile_options(${PROJECT_NAME} PRIVATE
      -Wno-deprecated-declarations
      -Os
      -mmacosx-version-min=11.01
      -ffunction-sections 
      -fdata-sections 
      -Wl,--gc-sections
    )
elseif(UNIX)
    # Linux / otros UNIX
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(GTK3 REQUIRED gtk+-3.0)
    pkg_check_modules(GLIB2 REQUIRED glib-2.0)
    pkg_check_modules(XCB REQUIRED xcb)
    pkg_check_modules(X11 REQUIRED x11)
    pkg_check_modules(XRANDR REQUIRED xrandr)
    
    target_include_directories(${PROJECT_NAME} PRIVATE 
      ${GTK3_INCLUDE_DIRS}
      ${GLIB2_INCLUDE_DIRS}
      ${XCB_INCLUDE_DIRS}
      ${X11_INCLUDE_DIRS}
      ${XRANDR_INCLUDE_DIRS}
    )
    
    target_link_libraries(${PROJECT_NAME} PRIVATE
      ${GTK3_LIBRARIES}
      ${GLIB2_LIBRARIES}
      ${XCB_LIBRARIES}
      ${X11_LIBRARIES}
      ${XRANDR_LIBRARIES}
      pthread
      png
      stdc++fs
      dl
    )
    
    target_compile_options(${PROJECT_NAME} PRIVATE 
      -no-pie
      -Os
      -ffunction-sections 
      -fdata-sections 
      -Wl,--gc-sections
    )
endif()

# =========================
# Additional optional configuration
# =========================
set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_STANDARD ${NEU_CXX_STANDARD}
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)