/*
 * S.T.A.R. - System Threat & Anomaly Radar
 * Core type definitions and data structures
 *
 * Copyright (C) 2026 Naveed Gung
 * Licensed under GPLv3 - see LICENSE file
 */

#ifndef STAR_TYPES_H
#define STAR_TYPES_H

#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32
    #include <windows.h>
    #define STAR_EXPORT __declspec(dllexport)
    #define STAR_CALL   __stdcall
#else
    #define STAR_EXPORT __attribute__((visibility("default")))
    #define STAR_CALL
#endif

/* ============================================================
 * Constants
 * ============================================================ */

#define STAR_VERSION_MAJOR    0
#define STAR_VERSION_MINOR    1
#define STAR_VERSION_PATCH    0
#define STAR_VERSION_STRING   "0.1.0"

#define STAR_MAX_PROCESS_NAME 256
#define STAR_MAX_DETECTION_TYPE 64
#define STAR_MAX_DESCRIPTION  512
#define STAR_STACK_TRACE_SIZE 512
#define STAR_MAX_PATH         1024

#define STAR_THREAT_SCORE_MIN 0
#define STAR_THREAT_SCORE_MAX 1000

/* ============================================================
 * Enumerations
 * ============================================================ */

/* Detection classification categories */
typedef enum _DETECTION_CLASS {
    DETECTION_CLASS_MEMORY   = 0,
    DETECTION_CLASS_HOOK     = 1,
    DETECTION_CLASS_BEHAVIOR = 2,
    DETECTION_CLASS_NETWORK  = 3,
    DETECTION_CLASS_KERNEL   = 4,
    DETECTION_CLASS_COUNT
} DETECTION_CLASS;

/* Event priority levels */
typedef enum _EVENT_PRIORITY {
    EVENT_PRIORITY_LOW      = 0,
    EVENT_PRIORITY_MEDIUM   = 1,
    EVENT_PRIORITY_HIGH     = 2,
    EVENT_PRIORITY_CRITICAL = 3,
    EVENT_PRIORITY_COUNT
} EVENT_PRIORITY;

/* Kernel event types */
typedef enum _KERNEL_EVENT_TYPE {
    KEVENT_PROCESS_CREATE   = 0x0001,
    KEVENT_PROCESS_EXIT     = 0x0002,
    KEVENT_THREAD_CREATE    = 0x0003,
    KEVENT_THREAD_EXIT      = 0x0004,
    KEVENT_IMAGE_LOAD       = 0x0010,
    KEVENT_MEMORY_ALLOC     = 0x0020,
    KEVENT_MEMORY_PROTECT   = 0x0021,
    KEVENT_HANDLE_CREATE    = 0x0030,
    KEVENT_HANDLE_DUP       = 0x0031,
    KEVENT_NETWORK_CONNECT  = 0x0040,
    KEVENT_NETWORK_LISTEN   = 0x0041,
    KEVENT_REGISTRY_WRITE   = 0x0050,
    KEVENT_FILE_CREATE      = 0x0060,
    KEVENT_HOOK_DETECTED    = 0x0100,
    KEVENT_INJECTION_DETECTED = 0x0200
} KERNEL_EVENT_TYPE;

/* MITRE ATT&CK technique identifiers (subset) */
typedef enum _MITRE_TECHNIQUE {
    MITRE_NONE              = 0,
    MITRE_T1055_001,    /* Process Injection: DLL Injection */
    MITRE_T1055_002,    /* Process Injection: PE Injection */
    MITRE_T1055_003,    /* Process Injection: Thread Execution Hijacking */
    MITRE_T1055_004,    /* Process Injection: Asynchronous Procedure Call */
    MITRE_T1055_012,    /* Process Injection: Process Hollowing */
    MITRE_T1014,        /* Rootkit */
    MITRE_T1562_001,    /* Impair Defenses: Disable or Modify Tools */
    MITRE_T1134,        /* Access Token Manipulation */
    MITRE_T1574,        /* Hijack Execution Flow */
    MITRE_T1547,        /* Boot or Logon Autostart Execution */
    MITRE_T1543,        /* Create or Modify System Process */
    MITRE_T1068,        /* Exploitation for Privilege Escalation */
    MITRE_T1071,        /* Application Layer Protocol */
    MITRE_TECHNIQUE_COUNT
} MITRE_TECHNIQUE;

/* Scan operation status */
typedef enum _STAR_STATUS {
    STAR_STATUS_OK          = 0,
    STAR_STATUS_ERROR       = -1,
    STAR_STATUS_NO_MEMORY   = -2,
    STAR_STATUS_ACCESS_DENIED = -3,
    STAR_STATUS_NOT_FOUND   = -4,
    STAR_STATUS_TIMEOUT     = -5,
    STAR_STATUS_UNSUPPORTED = -6
} STAR_STATUS;

/* ============================================================
 * Core Data Structures
 * ============================================================ */

/* Detection entry - represents a single detected threat/anomaly */
typedef struct _STAR_DETECTION {
    uint64_t        detection_id;
    uint32_t        pid;
    uint32_t        ppid;
    char            process_name[STAR_MAX_PROCESS_NAME];
    char            detection_type[STAR_MAX_DETECTION_TYPE];
    DETECTION_CLASS detection_class;
    uint64_t        address;
    uint32_t        threat_score;       /* 0-1000 */
    uint8_t         confidence;         /* 0-100% */
    MITRE_TECHNIQUE mitre_id;
    char            description[STAR_MAX_DESCRIPTION];
    uint64_t        timestamp_ns;
    EVENT_PRIORITY  priority;
    struct _STAR_DETECTION *next;
} STAR_DETECTION;

/* Kernel communication structure */
typedef struct _KERNEL_EVENT {
    uint32_t        event_type;
    uint32_t        pid;
    uint64_t        address;
    uint64_t        additional_info[4];
    uint8_t         stack_trace[STAR_STACK_TRACE_SIZE];
    uint64_t        timestamp;
} KERNEL_EVENT;

/* Behavioral profile for a process */
typedef struct _BEHAVIOR_PROFILE {
    uint32_t        pid;
    uint32_t        normal_syscalls[256];
    uint64_t        avg_memory_usage;
    uint32_t        avg_thread_count;
    uint32_t        typical_handles[10];
    uint64_t        network_connections[20];
    uint64_t        last_updated;
    bool            baseline_established;
} BEHAVIOR_PROFILE;

/* Process information structure */
typedef struct _STAR_PROCESS_INFO {
    uint32_t        pid;
    uint32_t        ppid;
    char            name[STAR_MAX_PROCESS_NAME];
    char            path[STAR_MAX_PATH];
    uint64_t        base_address;
    uint64_t        memory_usage;
    uint32_t        thread_count;
    uint32_t        handle_count;
    uint64_t        create_time;
    bool            is_hidden;
    bool            is_elevated;
    struct _STAR_PROCESS_INFO *next;
} STAR_PROCESS_INFO;

/* Memory region descriptor */
typedef struct _STAR_MEMORY_REGION {
    uint64_t        base_address;
    uint64_t        size;
    uint32_t        protection;     /* PAGE_EXECUTE_READWRITE, etc. */
    uint32_t        type;           /* MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE */
    bool            is_executable;
    bool            is_writable;
    bool            has_pe_header;
    char            mapped_file[STAR_MAX_PATH];
    struct _STAR_MEMORY_REGION *next;
} STAR_MEMORY_REGION;

/* Detection list container */
typedef struct _STAR_DETECTION_LIST {
    STAR_DETECTION  *head;
    STAR_DETECTION  *tail;
    uint32_t        count;
} STAR_DETECTION_LIST;

/* Process list container */
typedef struct _STAR_PROCESS_LIST {
    STAR_PROCESS_INFO *head;
    STAR_PROCESS_INFO *tail;
    uint32_t          count;
} STAR_PROCESS_LIST;

#endif /* STAR_TYPES_H */
