/*
 * S.T.A.R. - System Threat & Anomaly Radar
 * Core detection engine implementation
 *
 * Copyright (C) 2026 Naveed Gung
 * Licensed under GPLv3 - see LICENSE file
 */

#include "../include/star_detection.h"
#include "../include/star_event.h"
#include "../include/star_platform.h"
#include "../include/star_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Internal state */
static STAR_DETECTION_CONFIG g_config;
static bool g_engine_initialized = false;
static STAR_EVENT_QUEUE g_event_queue;

/* Forward declarations for module scans */
extern STAR_STATUS star_detect_memory_anomalies(uint32_t pid,
                                                STAR_DETECTION_LIST *results);
extern STAR_STATUS star_detect_hooks(STAR_DETECTION_LIST *results);
extern STAR_STATUS star_detect_behavior_anomalies(uint32_t pid,
                                                  STAR_DETECTION_LIST *results);
extern STAR_STATUS star_detect_kernel_anomalies(STAR_DETECTION_LIST *results);

/* ============================================================
 * Lifecycle Management
 * ============================================================ */

/* Whitelist of processes to ignore (JIT compilers, browsers, etc.) to reduce
 * noise */
static const char *g_process_whitelist[] = {
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "Code.exe",
    "discord.exe",
    "slack.exe",
    "Teams.exe",
    "node.exe",
    "electron.exe",
    "star-daemon.exe",
    "svchost.exe",
    "csrss.exe",
    "explorer.exe", /* Standard Windows noise for now */
    NULL};

static bool is_whitelisted(const char *name) {
  if (!name)
    return false;

  /* Extract filename if path is provided */
  const char *filename = strrchr(name, '\\');
  if (filename) {
    filename++; /* Skip the backslash */
  } else {
    filename = name;
  }

  /* Also try forward slash just in case */
  const char *fslash = strrchr(filename, '/');
  if (fslash) {
    filename = fslash + 1;
  }

  for (int i = 0; g_process_whitelist[i] != NULL; i++) {
    if (_stricmp(filename, g_process_whitelist[i]) == 0) {
      return true;
    }
  }
  return false;
}

STAR_STATUS star_detection_init(const STAR_DETECTION_CONFIG *config) {
  if (g_engine_initialized)
    return STAR_STATUS_OK;
  if (!config)
    return STAR_STATUS_ERROR;

  memcpy(&g_config, config, sizeof(STAR_DETECTION_CONFIG));

  /* Initialize event queue */
  if (star_event_queue_init(&g_event_queue) != STAR_STATUS_OK) {
    return STAR_STATUS_ERROR;
  }

  g_engine_initialized = true;
  return STAR_STATUS_OK;
}

void star_detection_shutdown(void) {
  if (!g_engine_initialized)
    return;

  star_event_queue_destroy(&g_event_queue);
  g_engine_initialized = false;
}

/* ============================================================
 * Scan Operations
 * ============================================================ */

STAR_STATUS star_detection_full_scan(STAR_DETECTION_LIST *results) {
  if (!g_engine_initialized || !results)
    return STAR_STATUS_ERROR;

  STAR_STATUS status = STAR_STATUS_OK;

  /* 1. Global System Checks (Hooks, Kernel) */
  if (g_config.enable_hook_detection) {
    star_detect_hooks(results);
  }

  if (g_config.enable_kernel_analysis) {
    star_detect_kernel_anomalies(results);
  }

  /* 2. Process Enumeration */
  STAR_PROCESS_LIST processes = {0};
  if (star_platform_enum_processes(&processes) == STAR_STATUS_OK) {

    STAR_PROCESS_INFO *curr = processes.head;
    while (curr) {
      if (!is_whitelisted(curr->name)) {
        /* 3. Per-Process Checks (Memory, Behavior) */
        star_detection_scan_process(curr->pid, results);
      }
      curr = curr->next;
    }

    star_process_list_free(&processes);
  } else {
    status = STAR_STATUS_ERROR;
  }

  return status;
}

STAR_STATUS star_detection_scan_process(uint32_t pid,
                                        STAR_DETECTION_LIST *results) {

  if (!g_engine_initialized || !results)
    return STAR_STATUS_ERROR;

  if (g_config.enable_memory_scan) {
    star_detect_memory_anomalies(pid, results);
  }

  if (g_config.enable_behavior_analysis) {
    star_detect_behavior_anomalies(pid, results);
  }

  return STAR_STATUS_OK;
}

/* ============================================================
 * Scoring & Classification
 * ============================================================ */

uint32_t star_detection_calculate_score(const STAR_DETECTION *detection) {
  if (!detection)
    return 0;

  uint32_t score = 0;

  /* Base score by priority */
  switch (detection->priority) {
  case EVENT_PRIORITY_CRITICAL:
    score = 900;
    break;
  case EVENT_PRIORITY_HIGH:
    score = 700;
    break;
  case EVENT_PRIORITY_MEDIUM:
    score = 400;
    break;
  case EVENT_PRIORITY_LOW:
    score = 100;
    break;
  default:
    score = 0;
    break;
  }

  /* Adjust by confidence */
  score = (score * detection->confidence) / 100;

  /* Clamp to max */
  if (score > STAR_THREAT_SCORE_MAX)
    score = STAR_THREAT_SCORE_MAX;

  return score;
}

MITRE_TECHNIQUE star_detection_map_mitre(const STAR_DETECTION *detection) {
  if (!detection)
    return MITRE_NONE;
  return detection->mitre_id; /* Already set during detection */
}
