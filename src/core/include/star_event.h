/*
 * S.T.A.R. - System Threat & Anomaly Radar
 * Event queue and ring buffer API
 *
 * Copyright (C) 2026 Naveed Gung
 * Licensed under GPLv3 - see LICENSE file
 */

#ifndef STAR_EVENT_H
#define STAR_EVENT_H

#include "star_types.h"

/* ============================================================
 * Ring Buffer (Lock-Free Kernel-to-User Communication)
 * ============================================================ */

#define STAR_RING_BUFFER_DEFAULT_SIZE 4096

typedef struct _STAR_RING_BUFFER {
    KERNEL_EVENT    *buffer;
    uint32_t        capacity;
    volatile uint32_t write_index;
    volatile uint32_t read_index;
} STAR_RING_BUFFER;

/*
 * Allocate and initialize a ring buffer with the given capacity.
 * Capacity must be a power of 2.
 */
STAR_STATUS star_ring_buffer_init(STAR_RING_BUFFER *rb, uint32_t capacity);

/*
 * Free ring buffer resources.
 */
void star_ring_buffer_destroy(STAR_RING_BUFFER *rb);

/*
 * Push an event into the ring buffer.
 * Returns STAR_STATUS_NO_MEMORY if the buffer is full.
 * Thread-safe for single producer.
 */
STAR_STATUS star_ring_buffer_push(STAR_RING_BUFFER *rb, const KERNEL_EVENT *event);

/*
 * Pop an event from the ring buffer.
 * Returns STAR_STATUS_NOT_FOUND if the buffer is empty.
 * Thread-safe for single consumer.
 */
STAR_STATUS star_ring_buffer_pop(STAR_RING_BUFFER *rb, KERNEL_EVENT *event);

/*
 * Get the number of events currently in the buffer.
 */
uint32_t star_ring_buffer_count(const STAR_RING_BUFFER *rb);

/*
 * Check if the ring buffer is empty.
 */
bool star_ring_buffer_is_empty(const STAR_RING_BUFFER *rb);

/*
 * Check if the ring buffer is full.
 */
bool star_ring_buffer_is_full(const STAR_RING_BUFFER *rb);

/* ============================================================
 * Event Queue (Priority-Based Processing)
 * ============================================================ */

typedef struct _STAR_EVENT_QUEUE {
    STAR_DETECTION_LIST queues[EVENT_PRIORITY_COUNT];
    uint32_t            total_count;
    bool                running;
} STAR_EVENT_QUEUE;

/*
 * Initialize the event queue.
 */
STAR_STATUS star_event_queue_init(STAR_EVENT_QUEUE *eq);

/*
 * Destroy the event queue and free all pending events.
 */
void star_event_queue_destroy(STAR_EVENT_QUEUE *eq);

/*
 * Enqueue a detection with its assigned priority.
 * The detection is copied into the queue.
 */
STAR_STATUS star_event_queue_push(STAR_EVENT_QUEUE *eq, const STAR_DETECTION *detection);

/*
 * Dequeue the highest-priority detection.
 * Returns STAR_STATUS_NOT_FOUND if all queues are empty.
 * Caller takes ownership of the returned detection.
 */
STAR_STATUS star_event_queue_pop(STAR_EVENT_QUEUE *eq, STAR_DETECTION *detection);

/*
 * Get total number of pending events across all priorities.
 */
uint32_t star_event_queue_count(const STAR_EVENT_QUEUE *eq);

/* ============================================================
 * Event Callback System
 * ============================================================ */

/* Callback function type for event notifications */
typedef void (*star_event_callback_fn)(const STAR_DETECTION *detection, void *user_data);

/*
 * Register a callback to be invoked when events of a given
 * priority (or higher) are enqueued.
 */
STAR_STATUS star_event_register_callback(
    EVENT_PRIORITY min_priority,
    star_event_callback_fn callback,
    void *user_data
);

/*
 * Unregister a previously registered callback.
 */
STAR_STATUS star_event_unregister_callback(star_event_callback_fn callback);

#endif /* STAR_EVENT_H */
