/*
 * S.T.A.R. - System Threat & Anomaly Radar
 * Common platform-independent utilities
 *
 * Copyright (C) 2026 Naveed Gung
 * Licensed under GPLv3 - see LICENSE file
 */

#include "../include/star_detection.h"
#include "../include/star_platform.h"
#include "../include/star_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================
 * Detection List Management
 * ============================================================ */

static STAR_DETECTION *star_detection_alloc(void) {
  STAR_DETECTION *det = (STAR_DETECTION *)calloc(1, sizeof(STAR_DETECTION));
  return det;
}

void star_detection_list_free(STAR_DETECTION_LIST *list) {
  if (!list)
    return;

  STAR_DETECTION *current = list->head;
  while (current) {
    STAR_DETECTION *next = current->next;
    free(current);
    current = next;
  }
  list->head = NULL;
  list->tail = NULL;
  list->count = 0;
}

STAR_STATUS star_detection_list_append(STAR_DETECTION_LIST *list,
                                       const STAR_DETECTION *detection) {
  if (!list || !detection)
    return STAR_STATUS_ERROR;

  STAR_DETECTION *copy = star_detection_alloc();
  if (!copy)
    return STAR_STATUS_NO_MEMORY;

  memcpy(copy, detection, sizeof(STAR_DETECTION));
  copy->next = NULL;

  if (!list->head) {
    list->head = copy;
    list->tail = copy;
  } else {
    list->tail->next = copy;
    list->tail = copy;
  }
  list->count++;
  return STAR_STATUS_OK;
}

/* ============================================================
 * Process List Management
 * ============================================================ */

void star_process_list_free(STAR_PROCESS_LIST *list) {
  if (!list)
    return;

  STAR_PROCESS_INFO *current = list->head;
  while (current) {
    STAR_PROCESS_INFO *next = current->next;
    free(current);
    current = next;
  }
  list->head = NULL;
  list->tail = NULL;
  list->count = 0;
}

STAR_STATUS star_process_list_append(STAR_PROCESS_LIST *list,
                                     const STAR_PROCESS_INFO *info) {
  if (!list || !info)
    return STAR_STATUS_ERROR;

  STAR_PROCESS_INFO *copy =
      (STAR_PROCESS_INFO *)calloc(1, sizeof(STAR_PROCESS_INFO));
  if (!copy)
    return STAR_STATUS_NO_MEMORY;

  memcpy(copy, info, sizeof(STAR_PROCESS_INFO));
  copy->next = NULL;

  if (!list->head) {
    list->head = copy;
    list->tail = copy;
  } else {
    list->tail->next = copy;
    list->tail = copy;
  }
  list->count++;
  return STAR_STATUS_OK;
}

/* ============================================================
 * Memory Region List Management
 * ============================================================ */

void star_memory_region_list_free(STAR_MEMORY_REGION *regions) {
  STAR_MEMORY_REGION *current = regions;
  while (current) {
    STAR_MEMORY_REGION *next = current->next;
    free(current);
    current = next;
  }
}

/* ============================================================
 * String Conversion Utilities
 * ============================================================ */

const char *star_detection_class_to_string(DETECTION_CLASS cls) {
  switch (cls) {
  case DETECTION_CLASS_MEMORY:
    return "Memory";
  case DETECTION_CLASS_HOOK:
    return "Hook";
  case DETECTION_CLASS_BEHAVIOR:
    return "Behavior";
  case DETECTION_CLASS_NETWORK:
    return "Network";
  case DETECTION_CLASS_KERNEL:
    return "Kernel";
  default:
    return "Unknown";
  }
}

const char *star_mitre_technique_to_string(MITRE_TECHNIQUE technique) {
  switch (technique) {
  case MITRE_NONE:
    return "N/A";
  case MITRE_T1055_001:
    return "T1055.001 - DLL Injection";
  case MITRE_T1055_002:
    return "T1055.002 - PE Injection";
  case MITRE_T1055_003:
    return "T1055.003 - Thread Execution Hijacking";
  case MITRE_T1055_004:
    return "T1055.004 - Asynchronous Procedure Call";
  case MITRE_T1055_012:
    return "T1055.012 - Process Hollowing";
  case MITRE_T1014:
    return "T1014 - Rootkit";
  case MITRE_T1562_001:
    return "T1562.001 - Disable or Modify Tools";
  case MITRE_T1134:
    return "T1134 - Access Token Manipulation";
  case MITRE_T1574:
    return "T1574 - Hijack Execution Flow";
  case MITRE_T1547:
    return "T1547 - Boot or Logon Autostart Execution";
  case MITRE_T1543:
    return "T1543 - Create or Modify System Process";
  case MITRE_T1068:
    return "T1068 - Exploitation for Privilege Escalation";
  case MITRE_T1071:
    return "T1071 - Application Layer Protocol";
  default:
    return "Unknown Technique";
  }
}

const char *star_event_priority_to_string(EVENT_PRIORITY priority) {
  switch (priority) {
  case EVENT_PRIORITY_LOW:
    return "Low";
  case EVENT_PRIORITY_MEDIUM:
    return "Medium";
  case EVENT_PRIORITY_HIGH:
    return "High";
  case EVENT_PRIORITY_CRITICAL:
    return "Critical";
  default:
    return "Unknown";
  }
}

const char *star_status_to_string(STAR_STATUS status) {
  switch (status) {
  case STAR_STATUS_OK:
    return "OK";
  case STAR_STATUS_ERROR:
    return "Error";
  case STAR_STATUS_NO_MEMORY:
    return "Out of memory";
  case STAR_STATUS_ACCESS_DENIED:
    return "Access denied";
  case STAR_STATUS_NOT_FOUND:
    return "Not found";
  case STAR_STATUS_TIMEOUT:
    return "Timeout";
  case STAR_STATUS_UNSUPPORTED:
    return "Unsupported";
  default:
    return "Unknown status";
  }
}

/*
 * Ring Buffer and Event Queue implementations have been moved to
 * event/star_event.c
 */
