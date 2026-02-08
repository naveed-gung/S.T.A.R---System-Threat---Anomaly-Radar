# ============================================================
# S.T.A.R. Daemon
# ============================================================

set(STAR_DAEMON_SOURCES
    main.c
    service.c
    daemon_core.c
    ipc.c
)

add_executable(star-daemon
    ${STAR_DAEMON_SOURCES}
)

target_include_directories(star-daemon
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src/core/include
)

target_link_libraries(star-daemon
    PRIVATE
        star_core
)

if(WIN32)
    target_link_libraries(star-daemon
        PRIVATE
            advapi32
    )
endif()

install(TARGETS star-daemon
    RUNTIME DESTINATION bin
)
