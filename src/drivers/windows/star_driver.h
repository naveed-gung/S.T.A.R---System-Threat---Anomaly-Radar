/*
 * S.T.A.R. - System Threat & Anomaly Radar
 * Windows Kernel Driver Header
 *
 * Copyright (C) 2026 Naveed Gung
 * Licensed under GPLv3 - see LICENSE file
 */

#ifndef STAR_DRIVER_H
#define STAR_DRIVER_H

#include <ntddk.h>

/* IOCTL Definitions (Placeholder) */
#define IOCTL_STAR_GET_VERSION                                                 \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#endif /* STAR_DRIVER_H */
