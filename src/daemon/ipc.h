/*
 * S.T.A.R. - System Threat & Anomaly Radar
 * IPC Interface (Named Pipes)
 *
 * Copyright (C) 2026 Naveed Gung
 * Licensed under GPLv3 - see LICENSE file
 */

#ifndef STAR_IPC_H
#define STAR_IPC_H

#include "../core/include/star_types.h"

/* Initialize the IPC subsystem (starts listener thread) */
STAR_STATUS star_ipc_init(void);

/* Shutdown IPC and close pipes */
void star_ipc_shutdown(void);

/* Send a detection event to the connected UI client */
void star_ipc_broadcast_event(const STAR_DETECTION *detection);

/* Check if a client is currently connected */
bool star_ipc_is_connected(void);

#endif /* STAR_IPC_H */
