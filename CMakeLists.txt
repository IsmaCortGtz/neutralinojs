cmake_minimum_required(VERSION 3.16)
set(NEU_VERSION "6.4.0")
set(NEU_CXX_STANDARD 17)

if(WIN32)
  cmake_policy(SET CMP0053 NEW)
  cmake_policy(SET CMP0010 NEW)
endif()

if(APPLE)
  project(NeutralinoJS LANGUAGES C CXX OBJC OBJCXX)
else()
  project(NeutralinoJS LANGUAGES C CXX)
endif()

execute_process(
  COMMAND git rev-parse HEAD
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE NEU_COMMIT
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET
)

# =========================
# Ensure submodules
# =========================
find_package(Git QUIET)

if(GIT_FOUND AND EXISTS "${CMAKE_SOURCE_DIR}/.git")
  option(GIT_SUBMODULE "Check submodules during build" ON)

  if(GIT_SUBMODULE)
    message(STATUS "Checking git submodules...")
    execute_process(
      COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive
      WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
      RESULT_VARIABLE GIT_SUBMOD_RESULT
    )

    if(NOT GIT_SUBMOD_RESULT EQUAL "0")
      message(FATAL_ERROR "Git submodule update failed")
    endif()
  endif()
endif()

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
  lib/miniz/*.c
  lib/brotli/**/*.c
  lib/pocket-http/*.cpp
)
list(APPEND SOURCES ${RECURSIVE_SOURCES})

if(WIN32)
  set(NEU_OS_NAME "win")
  file(GLOB_RECURSE OS_SOURCES
    lib/tinyprocess/process_win.cpp
    lib/clip/clip_win.cpp
    lib/efsw/src/efsw/platform/win/*.cpp
    lib/postject/windows_dummy.res
  )
  list(APPEND SOURCES ${OS_SOURCES})
  
  if(CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    message("Building Windows x64 🪟...")
    set(NEU_SYSTEM_PROCESSOR "x64")
  elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "IA64")
    message("Building Windows ia64 🪟...")
    set(NEU_SYSTEM_PROCESSOR "ia64")
  elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "i386" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "i686" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "x86")
    message("Building Windows x86 🪟...")
    set(NEU_SYSTEM_PROCESSOR "x86")
  elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "ARM64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
    message("Building Windows arm64 🪟...")
    set(NEU_SYSTEM_PROCESSOR "arm64")
  endif()
elseif(APPLE)
  set(NEU_OS_NAME "mac")
  file(GLOB_RECURSE OS_SOURCES
    lib/tinyprocess/process_unix.cpp
    lib/clip/clip_osx.mm
    lib/webview/macwindow.mm
    lib/efsw/src/efsw/platform/posix/*.cpp
  )
  list(APPEND SOURCES ${OS_SOURCES})

  # Force window.cpp to compile as Objective-C++ for ScreenCaptureKit support
  set_source_files_properties(
    ${PROJECT_SOURCE_DIR}/api/window/window.cpp
    PROPERTIES LANGUAGE OBJCXX
  )

  if(DEFINED CMAKE_OSX_ARCHITECTURES AND CMAKE_OSX_ARCHITECTURES STREQUAL "arm64")
    message("Building macOS arm64 🍏...")
    set(NEU_SYSTEM_PROCESSOR "arm64")
  elseif(DEFINED CMAKE_OSX_ARCHITECTURES AND CMAKE_OSX_ARCHITECTURES STREQUAL "x86_64")
    message("Building macOS x64 🍏...")
    set(NEU_SYSTEM_PROCESSOR "x64")
  elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "ARM64")
    message("Building macOS arm64 🍏...")
    set(NEU_SYSTEM_PROCESSOR "arm64")
  else()
    message("Building macOS x64 🍏...")
    set(NEU_SYSTEM_PROCESSOR "x64")
  endif()
elseif(UNIX)
  set(NEU_OS_NAME "linux")
  file(GLOB_RECURSE OS_SOURCES
    lib/tinyprocess/process_unix.cpp
    lib/clip/clip_x11.cpp
    lib/efsw/src/efsw/platform/posix/*.cpp
  )
  list(APPEND SOURCES ${OS_SOURCES})

  if(CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "x64")
    message("Building linux x64 🐧...")
    set(NEU_SYSTEM_PROCESSOR "x64")
  elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "i386" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "i686" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "x86" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "i486" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "i586")
    message("Building linux x86 🐧...")
    set(NEU_SYSTEM_PROCESSOR "x86")
  elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "ARM64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
    message("Building linux arm64 🐧...")
    set(NEU_SYSTEM_PROCESSOR "arm64")
  elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "armv7l" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "armv8l" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "armhf" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "arm" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "ARM32")
    message("Building linux armhf 🐧...")
    set(NEU_SYSTEM_PROCESSOR "armhf")
  endif()
endif()
list(FILTER SOURCES EXCLUDE REGEX ".*/asio/src/.*")

# =========================
# Create executable or library
# =========================
add_executable(${PROJECT_NAME} ${SOURCES})
set_target_properties(${PROJECT_NAME} PROPERTIES 
  OUTPUT_NAME "neutralino-${NEU_OS_NAME}_${NEU_SYSTEM_PROCESSOR}"
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin"
  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/bin"
  RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/bin"
)

# =========================
# Add MbedTLS external lib
# =========================
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "Build Mbed TLS static library" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "Disable shared mbedtls library" FORCE)

set(USE_STATIC_TF_PSA_CRYPTO_LIBRARY ON CACHE BOOL "Build TF-PSA-Crypto static" FORCE)
set(USE_SHARED_TF_PSA_CRYPTO_LIBRARY OFF CACHE BOOL "Disable TF-PSA-Crypto shared" FORCE)

# Workaround for Windows backslash issue in MbedTLS
# https://github.com/Mbed-TLS/mbedtls/issues/10502
set(GEN_FILES OFF CACHE BOOL "Disable generated files (Windows workaround)" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Disable BUILD_SHARED_LIBS globally" FORCE)
set(DISABLE_PACKAGE_CONFIG_AND_INSTALL ON CACHE BOOL "Disable package & install targets" FORCE)

set(MBEDTLS_USER_CONFIG_FILE "${PROJECT_SOURCE_DIR}/api/net/mbedtls_config_user.h" CACHE FILEPATH "Mbed TLS user config file" FORCE)
    
add_subdirectory(lib/mbedtls)
set(MBEDTLS_LINK_TARGETS "")

foreach(tg IN ITEMS MbedTLS::mbedtls MbedTLS::mbedx509)
  if(TARGET ${tg})
    list(APPEND MBEDTLS_LINK_TARGETS ${tg})
  endif()
endforeach()

if(MBEDTLS_LINK_TARGETS)
  message(STATUS "Linking with MbedTLS targets: ${MBEDTLS_LINK_TARGETS}")
  target_link_libraries(${PROJECT_NAME} PRIVATE ${MBEDTLS_LINK_TARGETS})
else()
  message(FATAL_ERROR "MbedTLS requested but no known Mbed TLS targets found after add_subdirectory(lib/mbedtls).")
endif()

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
  USE_POCKET_HTTP_MBEDTLS
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
  ${PROJECT_SOURCE_DIR}/lib/brotli/include
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
    )
    target_link_options(${PROJECT_NAME} PRIVATE
      /OPT:REF
      /OPT:ICF
      /SUBSYSTEM:WINDOWS
      /ENTRY:wWinMainCRTStartup
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
    find_library(SCREENCAPTUREKIT_FRAMEWORK ScreenCaptureKit)
    find_library(SECURITY_FRAMEWORK Security)
    target_link_libraries(${PROJECT_NAME} PRIVATE
      ${WebKit_FRAMEWORK}
      ${COCOA_FRAMEWORK}
      ${SCREENCAPTUREKIT_FRAMEWORK}
      ${SECURITY_FRAMEWORK}
    )
    target_compile_options(${PROJECT_NAME} PRIVATE
      -Wno-deprecated-declarations
      -Os
    )
    target_link_options(${PROJECT_NAME} PRIVATE
      -Wl,-dead_strip
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
    )
    target_link_options(${PROJECT_NAME} PRIVATE
      -Wl,--gc-sections  # Linux garbage collection
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