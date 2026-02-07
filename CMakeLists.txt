cmake_minimum_required(VERSION 3.16)

project(STAR
    VERSION 0.1.0
    DESCRIPTION "S.T.A.R. - System Threat & Anomaly Radar"
    LANGUAGES C
)

# ============================================================
# Build Configuration
# ============================================================

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Build type defaults to Release
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ============================================================
# Platform Detection
# ============================================================

if(WIN32)
    message(STATUS "Platform: Windows")
    add_definitions(-DSTAR_PLATFORM_WINDOWS=1)
    set(STAR_PLATFORM "windows")
elseif(UNIX AND NOT APPLE)
    message(STATUS "Platform: Linux")
    add_definitions(-DSTAR_PLATFORM_LINUX=1)
    set(STAR_PLATFORM "linux")
else()
    message(FATAL_ERROR "Unsupported platform. S.T.A.R. supports Windows and Linux only.")
endif()

# ============================================================
# Compiler Flags
# ============================================================

if(MSVC)
    add_compile_options(/W4 /WX- /D_CRT_SECURE_NO_WARNINGS)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(/Zi /Od)
    else()
        add_compile_options(/O2)
    endif()
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wformat=2)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-g -O0 -fsanitize=address -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address)
    else()
        add_compile_options(-O2)
    endif()
endif()

# ============================================================
# Sub-projects
# ============================================================

add_subdirectory(src/core)
