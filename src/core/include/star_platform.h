/*
 * S.T.A.R. - System Threat & Anomaly Radar
 * Cross-platform abstraction layer
 *
 * Copyright (C) 2026 Naveed Gung
 * Licensed under GPLv3 - see LICENSE file
 */

#ifndef STAR_PLATFORM_H
#define STAR_PLATFORM_H

#include "star_types.h"

/* ============================================================
 * Platform Detection
 * ============================================================ */

#if defined(_WIN32) || defined(_WIN64)
#define STAR_PLATFORM_WINDOWS 1
#define STAR_PLATFORM_NAME "Windows"
#elif defined(__linux__)
#define STAR_PLATFORM_LINUX 1
#define STAR_PLATFORM_NAME "Linux"
#else
#error "Unsupported platform. S.T.A.R. supports Windows and Linux only."
#endif

/* ============================================================
 * Platform Abstraction API
 *
 * All functions return STAR_STATUS codes.
 * Platform-specific implementations are in:
 *   - platform/windows/platform_win.c
 *   - platform/linux/platform_linux.c
 * ============================================================ */

/* --- Initialization & Cleanup --- */

/*
 * Initialize the platform layer.
 * Must be called before any other star_platform_* function.
 * Acquires necessary privileges and opens handles.
 */
STAR_STATUS star_platform_init(void);

/*
 * Cleanup the platform layer.
 * Releases all acquired resources and handles.
 */
void star_platform_cleanup(void);

/* --- Process Enumeration --- */

/*
 * Enumerate all running processes on the system.
 * Allocates and populates a linked list of STAR_PROCESS_INFO.
 * Caller must free the list with star_process_list_free().
 */
STAR_STATUS star_platform_enum_processes(STAR_PROCESS_LIST *list);

/*
 * Get detailed information about a specific process by PID.
 * Populates the provided STAR_PROCESS_INFO structure.
 */
STAR_STATUS star_platform_get_process_info(uint32_t pid,
                                           STAR_PROCESS_INFO *info);

/* --- Memory Analysis --- */

/*
 * Enumerate memory regions of a target process.
 * Allocates and populates a linked list of STAR_MEMORY_REGION.
 * Caller must free the list with star_memory_region_list_free().
 */
STAR_STATUS star_platform_enum_memory_regions(uint32_t pid,
                                              STAR_MEMORY_REGION **regions);

/*
 * Read memory from a target process.
 * buffer must be pre-allocated with at least 'size' bytes.
 * bytes_read receives the actual number of bytes read.
 */
STAR_STATUS star_platform_read_process_memory(uint32_t pid, uint64_t address,
                                              void *buffer, size_t size,
                                              size_t *bytes_read);

/* --- Kernel Structure Access --- */

/*
 * Check SSDT (Windows) or sys_call_table (Linux) integrity.
 * Returns detections for any hooked entries.
 */
STAR_STATUS star_platform_check_syscall_table(STAR_DETECTION_LIST *detections);

/*
 * Check IDT (Interrupt Descriptor Table) integrity.
 * Returns detections for any hooked interrupt handlers.
 */
STAR_STATUS star_platform_check_idt(STAR_DETECTION_LIST *detections);

/* --- System Information --- */

/*
 * Get the current system timestamp in nanoseconds.
 */
uint64_t star_platform_get_timestamp_ns(void);

/*
 * Get the number of logical CPU cores.
 */
uint32_t star_platform_get_cpu_count(void);

/*
 * Get total physical memory in bytes.
 */
uint64_t star_platform_get_total_memory(void);

/* --- Utility --- */

/*
 * Elevate privileges if possible (SeDebugPrivilege on Windows, CAP_SYS_PTRACE
 * on Linux). Returns STAR_STATUS_ACCESS_DENIED if elevation fails.
 */
STAR_STATUS star_platform_elevate_privileges(void);

/* --- Resource Cleanup Helpers --- */

void star_process_list_free(STAR_PROCESS_LIST *list);
void star_memory_region_list_free(STAR_MEMORY_REGION *regions);
void star_detection_list_free(STAR_DETECTION_LIST *list);
STAR_STATUS star_detection_list_append(STAR_DETECTION_LIST *list,
                                       const STAR_DETECTION *detection);

#endif /* STAR_PLATFORM_H */
