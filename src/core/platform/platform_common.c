/*
 * S.T.A.R. - System Threat & Anomaly Radar
 * Common platform-independent utilities
 *
 * Copyright (C) 2026 Naveed Gung
 * Licensed under GPLv3 - see LICENSE file
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../include/star_types.h"
#include "../include/star_platform.h"

/* ============================================================
 * Detection List Management
 * ============================================================ */

static STAR_DETECTION* star_detection_alloc(void)
{
    STAR_DETECTION *det = (STAR_DETECTION *)calloc(1, sizeof(STAR_DETECTION));
    return det;
}

void star_detection_list_free(STAR_DETECTION_LIST *list)
{
    if (!list) return;

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

STAR_STATUS star_detection_list_append(STAR_DETECTION_LIST *list, const STAR_DETECTION *detection)
{
    if (!list || !detection) return STAR_STATUS_ERROR;

    STAR_DETECTION *copy = star_detection_alloc();
    if (!copy) return STAR_STATUS_NO_MEMORY;

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

void star_process_list_free(STAR_PROCESS_LIST *list)
{
    if (!list) return;

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

STAR_STATUS star_process_list_append(STAR_PROCESS_LIST *list, const STAR_PROCESS_INFO *info)
{
    if (!list || !info) return STAR_STATUS_ERROR;

    STAR_PROCESS_INFO *copy = (STAR_PROCESS_INFO *)calloc(1, sizeof(STAR_PROCESS_INFO));
    if (!copy) return STAR_STATUS_NO_MEMORY;

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

void star_memory_region_list_free(STAR_MEMORY_REGION *regions)
{
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

const char* star_detection_class_to_string(DETECTION_CLASS cls)
{
    switch (cls) {
        case DETECTION_CLASS_MEMORY:   return "Memory";
        case DETECTION_CLASS_HOOK:     return "Hook";
        case DETECTION_CLASS_BEHAVIOR: return "Behavior";
        case DETECTION_CLASS_NETWORK:  return "Network";
        case DETECTION_CLASS_KERNEL:   return "Kernel";
        default:                       return "Unknown";
    }
}

const char* star_mitre_technique_to_string(MITRE_TECHNIQUE technique)
{
    switch (technique) {
        case MITRE_NONE:        return "N/A";
        case MITRE_T1055_001:   return "T1055.001 - DLL Injection";
        case MITRE_T1055_002:   return "T1055.002 - PE Injection";
        case MITRE_T1055_003:   return "T1055.003 - Thread Execution Hijacking";
        case MITRE_T1055_004:   return "T1055.004 - Asynchronous Procedure Call";
        case MITRE_T1055_012:   return "T1055.012 - Process Hollowing";
        case MITRE_T1014:       return "T1014 - Rootkit";
        case MITRE_T1562_001:   return "T1562.001 - Disable or Modify Tools";
        case MITRE_T1134:       return "T1134 - Access Token Manipulation";
        case MITRE_T1574:       return "T1574 - Hijack Execution Flow";
        case MITRE_T1547:       return "T1547 - Boot or Logon Autostart Execution";
        case MITRE_T1543:       return "T1543 - Create or Modify System Process";
        case MITRE_T1068:       return "T1068 - Exploitation for Privilege Escalation";
        case MITRE_T1071:       return "T1071 - Application Layer Protocol";
        default:                return "Unknown Technique";
    }
}

const char* star_event_priority_to_string(EVENT_PRIORITY priority)
{
    switch (priority) {
        case EVENT_PRIORITY_LOW:      return "Low";
        case EVENT_PRIORITY_MEDIUM:   return "Medium";
        case EVENT_PRIORITY_HIGH:     return "High";
        case EVENT_PRIORITY_CRITICAL: return "Critical";
        default:                      return "Unknown";
    }
}

const char* star_status_to_string(STAR_STATUS status)
{
    switch (status) {
        case STAR_STATUS_OK:            return "OK";
        case STAR_STATUS_ERROR:         return "Error";
        case STAR_STATUS_NO_MEMORY:     return "Out of memory";
        case STAR_STATUS_ACCESS_DENIED: return "Access denied";
        case STAR_STATUS_NOT_FOUND:     return "Not found";
        case STAR_STATUS_TIMEOUT:       return "Timeout";
        case STAR_STATUS_UNSUPPORTED:   return "Unsupported";
        default:                        return "Unknown status";
    }
}

/* ============================================================
 * Ring Buffer Implementation
 * ============================================================ */

static bool is_power_of_two(uint32_t n)
{
    return n && !(n & (n - 1));
}

STAR_STATUS star_ring_buffer_init(STAR_RING_BUFFER *rb, uint32_t capacity)
{
    if (!rb) return STAR_STATUS_ERROR;
    if (!is_power_of_two(capacity)) return STAR_STATUS_ERROR;

    rb->buffer = (KERNEL_EVENT *)calloc(capacity, sizeof(KERNEL_EVENT));
    if (!rb->buffer) return STAR_STATUS_NO_MEMORY;

    rb->capacity = capacity;
    rb->write_index = 0;
    rb->read_index = 0;
    return STAR_STATUS_OK;
}

void star_ring_buffer_destroy(STAR_RING_BUFFER *rb)
{
    if (!rb) return;
    free(rb->buffer);
    rb->buffer = NULL;
    rb->capacity = 0;
    rb->write_index = 0;
    rb->read_index = 0;
}

STAR_STATUS star_ring_buffer_push(STAR_RING_BUFFER *rb, const KERNEL_EVENT *event)
{
    if (!rb || !event || !rb->buffer) return STAR_STATUS_ERROR;

    uint32_t next_write = (rb->write_index + 1) & (rb->capacity - 1);
    if (next_write == rb->read_index) {
        return STAR_STATUS_NO_MEMORY; /* Buffer full */
    }

    memcpy(&rb->buffer[rb->write_index], event, sizeof(KERNEL_EVENT));
    rb->write_index = next_write;
    return STAR_STATUS_OK;
}

STAR_STATUS star_ring_buffer_pop(STAR_RING_BUFFER *rb, KERNEL_EVENT *event)
{
    if (!rb || !event || !rb->buffer) return STAR_STATUS_ERROR;

    if (rb->read_index == rb->write_index) {
        return STAR_STATUS_NOT_FOUND; /* Buffer empty */
    }

    memcpy(event, &rb->buffer[rb->read_index], sizeof(KERNEL_EVENT));
    rb->read_index = (rb->read_index + 1) & (rb->capacity - 1);
    return STAR_STATUS_OK;
}

uint32_t star_ring_buffer_count(const STAR_RING_BUFFER *rb)
{
    if (!rb) return 0;
    return (rb->write_index - rb->read_index) & (rb->capacity - 1);
}

bool star_ring_buffer_is_empty(const STAR_RING_BUFFER *rb)
{
    if (!rb) return true;
    return rb->read_index == rb->write_index;
}

bool star_ring_buffer_is_full(const STAR_RING_BUFFER *rb)
{
    if (!rb) return true;
    return ((rb->write_index + 1) & (rb->capacity - 1)) == rb->read_index;
}

/* ============================================================
 * Event Queue Implementation
 * ============================================================ */

STAR_STATUS star_event_queue_init(STAR_EVENT_QUEUE *eq)
{
    if (!eq) return STAR_STATUS_ERROR;
    memset(eq, 0, sizeof(STAR_EVENT_QUEUE));
    eq->running = true;
    return STAR_STATUS_OK;
}

void star_event_queue_destroy(STAR_EVENT_QUEUE *eq)
{
    if (!eq) return;
    for (int i = 0; i < EVENT_PRIORITY_COUNT; i++) {
        star_detection_list_free(&eq->queues[i]);
    }
    eq->total_count = 0;
    eq->running = false;
}

STAR_STATUS star_event_queue_push(STAR_EVENT_QUEUE *eq, const STAR_DETECTION *detection)
{
    if (!eq || !detection) return STAR_STATUS_ERROR;
    if (!eq->running) return STAR_STATUS_ERROR;

    int priority = detection->priority;
    if (priority < 0 || priority >= EVENT_PRIORITY_COUNT) {
        priority = EVENT_PRIORITY_LOW;
    }

    STAR_STATUS status = star_detection_list_append(&eq->queues[priority], detection);
    if (status == STAR_STATUS_OK) {
        eq->total_count++;
    }
    return status;
}

STAR_STATUS star_event_queue_pop(STAR_EVENT_QUEUE *eq, STAR_DETECTION *detection)
{
    if (!eq || !detection) return STAR_STATUS_ERROR;

    /* Dequeue from highest priority first */
    for (int i = EVENT_PRIORITY_COUNT - 1; i >= 0; i--) {
        STAR_DETECTION_LIST *queue = &eq->queues[i];
        if (queue->head) {
            STAR_DETECTION *head = queue->head;
            memcpy(detection, head, sizeof(STAR_DETECTION));
            detection->next = NULL;

            queue->head = head->next;
            if (!queue->head) {
                queue->tail = NULL;
            }
            queue->count--;
            eq->total_count--;
            free(head);
            return STAR_STATUS_OK;
        }
    }
    return STAR_STATUS_NOT_FOUND;
}

uint32_t star_event_queue_count(const STAR_EVENT_QUEUE *eq)
{
    if (!eq) return 0;
    return eq->total_count;
}
