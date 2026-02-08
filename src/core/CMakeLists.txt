cmake_minimum_required(VERSION 3.16)

# ============================================================
# S.T.A.R. Core Detection Engine Library
# ============================================================

set(STAR_CORE_HEADERS
    include/star_types.h
    include/star_platform.h
    include/star_detection.h
    include/star_event.h
)

set(STAR_CORE_SOURCES
    platform/platform_common.c
    event/star_event.c
    detection/star_detection.c
    detection/memory_scan.c
    detection/hook_scan.c
)

# Platform-specific sources
if(WIN32)
    list(APPEND STAR_CORE_SOURCES
        platform/windows/platform_win.c
    )
elseif(UNIX)
    list(APPEND STAR_CORE_SOURCES
        platform/linux/platform_linux.c
    )
endif()

# ============================================================
# Library Target
# ============================================================

add_library(star_core STATIC
    ${STAR_CORE_HEADERS}
    ${STAR_CORE_SOURCES}
)

target_include_directories(star_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# ============================================================
# Platform-Specific Link Libraries
# ============================================================

if(WIN32)
    target_link_libraries(star_core
        PRIVATE
            ntdll
            psapi
    )
elseif(UNIX)
    target_link_libraries(star_core
        PRIVATE
            rt
    )
endif()

# ============================================================
# Install Rules
# ============================================================

install(TARGETS star_core
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(FILES ${STAR_CORE_HEADERS}
    DESTINATION include/star
)
