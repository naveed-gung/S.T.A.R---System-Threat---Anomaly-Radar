/*
 * S.T.A.R. - System Threat & Anomaly Radar
 * Event system implementation
 *
 * Copyright (C) 2026 Naveed Gung
 * Licensed under GPLv3 - see LICENSE file
 */

#include "../include/star_event.h"
#include "../include/star_platform.h"
#include "../include/star_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================
 * Ring Buffer Implementation
 * ============================================================ */

/* Helper for atomic operations (compiler intrinsics) */
#if defined(_MSC_VER)
#include <windows.h>
#define ATOMIC_INC(ptr) InterlockedIncrement((LONG *)(ptr))
#define MEMORY_BARRIER() MemoryBarrier()
#else
#define ATOMIC_INC(ptr) __sync_add_and_fetch((ptr), 1)
#define MEMORY_BARRIER() __sync_synchronize()
#endif

STAR_STATUS star_ring_buffer_init(STAR_RING_BUFFER *rb, uint32_t capacity) {
  if (!rb)
    return STAR_STATUS_ERROR;

  /* Capacity must be power of 2 for fast wrapping */
  if (capacity == 0 || (capacity & (capacity - 1)) != 0) {
    return STAR_STATUS_ERROR;
  }

  rb->buffer = (KERNEL_EVENT *)calloc(capacity, sizeof(KERNEL_EVENT));
  if (!rb->buffer) {
    return STAR_STATUS_NO_MEMORY;
  }

  rb->capacity = capacity;
  rb->write_index = 0;
  rb->read_index = 0;

  return STAR_STATUS_OK;
}

void star_ring_buffer_destroy(STAR_RING_BUFFER *rb) {
  if (!rb)
    return;

  if (rb->buffer) {
    free(rb->buffer);
    rb->buffer = NULL;
  }
  rb->capacity = 0;
  rb->write_index = 0;
  rb->read_index = 0;
}

STAR_STATUS star_ring_buffer_push(STAR_RING_BUFFER *rb,
                                  const KERNEL_EVENT *event) {
  if (!rb || !event || !rb->buffer)
    return STAR_STATUS_ERROR;

  uint32_t current_write = rb->write_index;
  uint32_t next_write = (current_write + 1) & (rb->capacity - 1);

  /* Check if full */
  if (next_write == rb->read_index) {
    return STAR_STATUS_NO_MEMORY;
  }

  /* Copy event to buffer */
  memcpy(&rb->buffer[current_write], event, sizeof(KERNEL_EVENT));

  /* Ensure write is visible before updating index */
  MEMORY_BARRIER();

  rb->write_index = next_write;
  return STAR_STATUS_OK;
}

STAR_STATUS star_ring_buffer_pop(STAR_RING_BUFFER *rb, KERNEL_EVENT *event) {
  if (!rb || !event || !rb->buffer)
    return STAR_STATUS_ERROR;

  uint32_t current_read = rb->read_index;

  /* Check if empty */
  if (current_read == rb->write_index) {
    return STAR_STATUS_NOT_FOUND;
  }

  /* Copy event from buffer */
  memcpy(event, &rb->buffer[current_read], sizeof(KERNEL_EVENT));

  /* Ensure read is complete before updating index */
  MEMORY_BARRIER();

  rb->read_index = (current_read + 1) & (rb->capacity - 1);
  return STAR_STATUS_OK;
}

uint32_t star_ring_buffer_count(const STAR_RING_BUFFER *rb) {
  if (!rb)
    return 0;
  return (rb->write_index - rb->read_index) & (rb->capacity - 1);
}

bool star_ring_buffer_is_empty(const STAR_RING_BUFFER *rb) {
  return star_ring_buffer_count(rb) == 0;
}

bool star_ring_buffer_is_full(const STAR_RING_BUFFER *rb) {
  if (!rb)
    return true;
  return ((rb->write_index + 1) & (rb->capacity - 1)) == rb->read_index;
}

/* ============================================================
 * Event Queue Implementation
 * ============================================================ */

/* Callback List */
typedef struct _CALLBACK_NODE {
  EVENT_PRIORITY min_priority;
  star_event_callback_fn callback;
  void *user_data;
  struct _CALLBACK_NODE *next;
} CALLBACK_NODE;

static CALLBACK_NODE *g_callbacks = NULL;

STAR_STATUS star_event_queue_init(STAR_EVENT_QUEUE *eq) {
  if (!eq)
    return STAR_STATUS_ERROR;

  memset(eq, 0, sizeof(STAR_EVENT_QUEUE));
  eq->running = true;

  return STAR_STATUS_OK;
}

void star_event_queue_destroy(STAR_EVENT_QUEUE *eq) {
  if (!eq)
    return;

  eq->running = false;

  /* Clean up all queues */
  for (int i = 0; i < EVENT_PRIORITY_COUNT; i++) {
    star_detection_list_free(&eq->queues[i]);
  }

  eq->total_count = 0;
}

STAR_STATUS star_event_queue_push(STAR_EVENT_QUEUE *eq,
                                  const STAR_DETECTION *detection) {
  if (!eq || !detection)
    return STAR_STATUS_ERROR;

  /* Validate priority */
  EVENT_PRIORITY prio = detection->priority;
  if (prio >= EVENT_PRIORITY_COUNT) {
    prio = EVENT_PRIORITY_LOW;
  }

  STAR_STATUS status = star_detection_list_append(&eq->queues[prio], detection);
  if (status == STAR_STATUS_OK) {
    eq->total_count++;

    /* Notify callbacks */
    CALLBACK_NODE *curr = g_callbacks;
    while (curr) {
      if (prio >= curr->min_priority) {
        curr->callback(detection, curr->user_data);
      }
      curr = curr->next;
    }
  }

  return status;
}

STAR_STATUS star_event_queue_pop(STAR_EVENT_QUEUE *eq,
                                 STAR_DETECTION *detection) {
  if (!eq || !detection)
    return STAR_STATUS_ERROR;

  /* Check higher priorities first */
  for (int i = EVENT_PRIORITY_COUNT - 1; i >= 0; i--) {
    STAR_DETECTION_LIST *list = &eq->queues[i];

    if (list->head) {
      /* Copy data */
      memcpy(detection, list->head, sizeof(STAR_DETECTION));

      /* Remove from list */
      STAR_DETECTION *old_head = list->head;
      list->head = old_head->next;
      if (!list->head) {
        list->tail = NULL;
      }

      free(old_head);
      list->count--;
      eq->total_count--;

      return STAR_STATUS_OK;
    }
  }

  return STAR_STATUS_NOT_FOUND;
}

uint32_t star_event_queue_count(const STAR_EVENT_QUEUE *eq) {
  if (!eq)
    return 0;
  return eq->total_count;
}

/* ============================================================
 * Event Callback System
 * ============================================================ */

STAR_STATUS star_event_register_callback(EVENT_PRIORITY min_priority,
                                         star_event_callback_fn callback,
                                         void *user_data) {
  if (!callback)
    return STAR_STATUS_ERROR;

  CALLBACK_NODE *node = (CALLBACK_NODE *)malloc(sizeof(CALLBACK_NODE));
  if (!node)
    return STAR_STATUS_NO_MEMORY;

  node->min_priority = min_priority;
  node->callback = callback;
  node->user_data = user_data;
  node->next = g_callbacks;
  g_callbacks = node;

  return STAR_STATUS_OK;
}

STAR_STATUS star_event_unregister_callback(star_event_callback_fn callback) {
  if (!callback)
    return STAR_STATUS_ERROR;

  CALLBACK_NODE **curr = &g_callbacks;
  while (*curr) {
    if ((*curr)->callback == callback) {
      CALLBACK_NODE *to_free = *curr;
      *curr = to_free->next;
      free(to_free);
      return STAR_STATUS_OK;
    }
    curr = &(*curr)->next;
  }

  return STAR_STATUS_NOT_FOUND;
}
