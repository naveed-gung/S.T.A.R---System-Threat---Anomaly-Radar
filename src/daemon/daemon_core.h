/*
 * S.T.A.R. - System Threat & Anomaly Radar
 * Daemon Core Header
 *
 * Copyright (C) 2026 Naveed Gung
 * Licensed under GPLv3 - see LICENSE file
 */

#ifndef STAR_DAEMON_CORE_H
#define STAR_DAEMON_CORE_H

#include <stdbool.h>

/*
 * Main loop of the daemon.
 * if console_mode is true, runs with stdout logging and Ctrl+C handler.
 * if false, runs in service mode (logging to file/event log).
 */
int star_daemon_main_loop(bool console_mode);

/*
 * Signal the daemon to stop.
 * Thread-safe.
 */
void star_daemon_stop_signal(void);

#endif /* STAR_DAEMON_CORE_H */
