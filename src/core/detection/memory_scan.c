/*
 * S.T.A.R. - System Threat & Anomaly Radar
 * Memory anomaly detection
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
 * Internal Helpers
 * ============================================================ */

/* Check if region is RWX (Readable, Writable, Executable) - often shellcode */
static bool is_rwx_region(const STAR_MEMORY_REGION *region) {
  return (region->protection &
          (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
}

/* Check if region contains a PE/ELF header but is not backed by a disk image */
static bool is_reflective_dll(const STAR_MEMORY_REGION *region) {
  if (!region->has_pe_header)
    return false;

  /* If it has a PE header but type is MEM_PRIVATE or MEM_MAPPED (not image),
   * it's suspicious */
  return (region->type == MEM_PRIVATE || region->type == MEM_MAPPED);
}

/* ============================================================
 * Memory Scan Implementation
 * ============================================================ */

STAR_STATUS star_detect_memory_anomalies(uint32_t pid,
                                         STAR_DETECTION_LIST *results) {
  if (!results)
    return STAR_STATUS_ERROR;

  STAR_MEMORY_REGION *regions = NULL;
  if (star_platform_enum_memory_regions(pid, &regions) != STAR_STATUS_OK) {
    return STAR_STATUS_ERROR;
  }

  STAR_MEMORY_REGION *curr = regions;
  while (curr) {
    /* Check 1: RWX Pages (Shellcode) */
    if (is_rwx_region(curr)) {
      STAR_DETECTION detection;
      memset(&detection, 0, sizeof(detection));

      detection.pid = pid;
      detection.detection_class = DETECTION_CLASS_MEMORY;
      detection.priority = EVENT_PRIORITY_HIGH;
      detection.confidence = 80;
      detection.address = curr->base_address;
      detection.mitre_id = MITRE_T1055_001; /* DLL Injection / Shellcode */
      strncpy(detection.detection_type, "RWX_MEMORY_PAGE",
              STAR_MAX_DETECTION_TYPE - 1);
      snprintf(
          detection.description, STAR_MAX_DESCRIPTION,
          "Suspicious RWX memory page detected at 0x%llx (Size: %llu bytes)",
          curr->base_address, curr->size);

      star_detection_list_append(results, &detection);
    }

    /* Check 2: Reflective DLL Injection (PE Header in non-image memory) */
    if (is_reflective_dll(curr)) {
      STAR_DETECTION detection;
      memset(&detection, 0, sizeof(detection));

      detection.pid = pid;
      detection.detection_class = DETECTION_CLASS_MEMORY;
      detection.priority = EVENT_PRIORITY_CRITICAL;
      detection.confidence = 95;
      detection.address = curr->base_address;
      detection.mitre_id = MITRE_T1055_002; /* PE Injection */
      strncpy(detection.detection_type, "REFLECTIVE_DLL",
              STAR_MAX_DETECTION_TYPE - 1);
      snprintf(detection.description, STAR_MAX_DESCRIPTION,
               "Reflective DLL injection detected (PE header in private "
               "memory) at 0x%llx",
               curr->base_address);

      star_detection_list_append(results, &detection);
    }

    curr = curr->next;
  }

  star_memory_region_list_free(regions);
  return STAR_STATUS_OK;
}
