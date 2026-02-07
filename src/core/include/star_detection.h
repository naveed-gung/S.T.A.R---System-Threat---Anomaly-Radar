/*
 * S.T.A.R. - System Threat & Anomaly Radar
 * Detection engine API
 *
 * Copyright (C) 2026 Naveed Gung
 * Licensed under GPLv3 - see LICENSE file
 */

#ifndef STAR_DETECTION_H
#define STAR_DETECTION_H

#include "star_types.h"

/* ============================================================
 * Detection Engine Configuration
 * ============================================================ */

typedef struct _STAR_DETECTION_CONFIG {
    bool        enable_memory_scan;
    bool        enable_hook_detection;
    bool        enable_behavior_analysis;
    bool        enable_network_monitoring;
    bool        enable_kernel_analysis;
    uint32_t    scan_interval_ms;       /* Milliseconds between scans */
    uint32_t    threat_threshold;       /* Minimum score to report (0-1000) */
    uint8_t     confidence_threshold;   /* Minimum confidence to report (0-100) */
} STAR_DETECTION_CONFIG;

/* Default configuration */
#define STAR_DETECTION_CONFIG_DEFAULT { \
    .enable_memory_scan       = true,  \
    .enable_hook_detection    = true,  \
    .enable_behavior_analysis = true,  \
    .enable_network_monitoring = false, \
    .enable_kernel_analysis   = true,  \
    .scan_interval_ms         = 5000,  \
    .threat_threshold         = 100,   \
    .confidence_threshold     = 30     \
}

/* ============================================================
 * Detection Engine Lifecycle
 * ============================================================ */

/*
 * Initialize the detection engine with the given configuration.
 * Must be called after star_platform_init().
 */
STAR_STATUS star_detection_init(const STAR_DETECTION_CONFIG *config);

/*
 * Shutdown the detection engine and free all resources.
 */
void star_detection_shutdown(void);

/* ============================================================
 * Scan Operations
 * ============================================================ */

/*
 * Run a full system scan across all enabled detection modules.
 * Results are appended to the provided detection list.
 */
STAR_STATUS star_detection_full_scan(STAR_DETECTION_LIST *results);

/*
 * Scan a specific process by PID.
 * Runs memory analysis and behavioral checks on the target.
 */
STAR_STATUS star_detection_scan_process(uint32_t pid, STAR_DETECTION_LIST *results);

/* ============================================================
 * Module-Specific Scans
 * ============================================================ */

/*
 * Memory analysis: scan for reflective DLL injection,
 * RWX pages, PE headers in non-image memory, anomalous VADs.
 */
STAR_STATUS star_detect_memory_anomalies(uint32_t pid, STAR_DETECTION_LIST *results);

/*
 * Hook detection: check SSDT/sys_call_table, IDT, MSR,
 * IRP function tables, and driver dispatch routines.
 */
STAR_STATUS star_detect_hooks(STAR_DETECTION_LIST *results);

/*
 * Behavioral analysis: compare current process behavior
 * against established baselines.
 */
STAR_STATUS star_detect_behavior_anomalies(uint32_t pid, STAR_DETECTION_LIST *results);

/*
 * Kernel object analysis: detect DKOM, hidden processes,
 * unlinked list entries, and suspicious callbacks.
 */
STAR_STATUS star_detect_kernel_anomalies(STAR_DETECTION_LIST *results);

/* ============================================================
 * Scoring & Classification
 * ============================================================ */

/*
 * Calculate a multi-factor threat score for a detection.
 * Considers detection class, confidence, system context,
 * and MITRE ATT&CK mapping.
 */
uint32_t star_detection_calculate_score(const STAR_DETECTION *detection);

/*
 * Map a detection to the most likely MITRE ATT&CK technique.
 */
MITRE_TECHNIQUE star_detection_map_mitre(const STAR_DETECTION *detection);

/*
 * Get a human-readable string for a MITRE technique ID.
 */
const char* star_mitre_technique_to_string(MITRE_TECHNIQUE technique);

/*
 * Get a human-readable string for a detection class.
 */
const char* star_detection_class_to_string(DETECTION_CLASS cls);

#endif /* STAR_DETECTION_H */
