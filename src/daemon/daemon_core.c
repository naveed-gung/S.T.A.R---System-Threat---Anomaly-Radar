/*
 * S.T.A.R. - System Threat & Anomaly Radar
 * Daemon Core Implementation
 *
 * Copyright (C) 2026 Naveed Gung
 * Licensed under GPLv3 - see LICENSE file
 */

#include "daemon_core.h"
#include "../core/include/star_detection.h"
#include "../core/include/star_event.h"
#include "../core/include/star_platform.h"
#include "ipc.h"
#include <stdio.h>
#include <stdlib.h>
#include <windows.h> /* For Sleep */


static volatile bool g_running = false;
static bool g_console_mode = false;

void star_daemon_stop_signal(void) { g_running = false; }

static void log_message(const char *format, ...) {
  va_list args;
  va_start(args, format);

  if (g_console_mode) {
    vprintf(format, args);
    printf("\n");
  } else {
    /* TODO: Log to file or Windows Event Log */
  }

  va_end(args);
}

static void handle_detection(const STAR_DETECTION *detection, void *user_data) {
  (void)user_data;

  log_message("[ALERT] Priority: %d | Score: %u | Type: %s",
              detection->priority, star_detection_calculate_score(detection),
              detection->detection_type);

  log_message("        %s", detection->description);

  star_ipc_broadcast_event(detection);
}

int star_daemon_main_loop(bool console_mode) {
  g_console_mode = console_mode;
  g_running = true;

  log_message("S.T.A.R. Daemon Starting...");

  /* Initialize Platform */
  if (star_platform_init() != STAR_STATUS_OK) {
    log_message("Failed to initialize platform layer.");
    return 1;
  }

  /* Initialize Detection Engine */
  STAR_DETECTION_CONFIG config = {
      .enable_memory_scan = true,
      .enable_hook_detection = true,
      .enable_behavior_analysis = true,
      .enable_kernel_analysis = false /* Not yet implemented */
  };

  if (star_detection_init(&config) != STAR_STATUS_OK) {
    log_message("Failed to initialize detection engine.");
    star_platform_cleanup();
    return 1;
  }

  /* Initialize IPC */
  if (star_ipc_init() != STAR_STATUS_OK) {
    log_message("Failed to initialize IPC.");
    /* We could continue without IPC, but let's log error */
  }

  /* Register callback */
  star_event_register_callback(EVENT_PRIORITY_LOW, handle_detection, NULL);

  log_message("Engine initialized. Starting scan loop.");

  STAR_DETECTION_LIST results = {0};

  while (g_running) {
    /* Run Full Scan */
    /* Note: In a real system, this should be event-driven or smarter scheduling
     */
    log_message("Performing periodic system scan...");

    star_detection_full_scan(&results);

    /* Process results */
    STAR_DETECTION *curr = results.head;
    while (curr) {
      /* Handled by callback automatically if pushed to queue,
         but full_scan just returns a list.
         Let's create a helper to process the list via the event system
         or just log them here since we didn't fully integrate scan->event queue
         yet.
      */

      /* Logic gap: star_detection_full_scan returns a list,
         but star_event_queue_push expects single events.
         We can just log them directly here for now.
      */
      handle_detection(curr, NULL);

      curr = curr->next;
    }

    /* Clean up results for next run */
    /* Manual cleanup of the list nodes since we consumed them */
    star_detection_list_free(&results);
    memset(&results, 0, sizeof(results));

    /* Sleep for 5 seconds */
    Sleep(5000);
  }

  log_message("S.T.A.R. Daemon Stopping...");

  star_ipc_shutdown();
  star_detection_shutdown();
  star_platform_cleanup();

  return 0;
}
