/*
 * S.T.A.R. - System Threat & Anomaly Radar
 * Windows Kernel Driver Skeleton
 *
 * Copyright (C) 2026 Naveed Gung
 * Licensed under GPLv3 - see LICENSE file
 */

#include <ntddk.h>

/* Forward declarations */
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD StarDriverUnload;

/*
 * Driver Entry Point
 */
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(RegistryPath);

  DbgPrint("S.T.A.R. Driver Loaded\n");

  DriverObject->DriverUnload = StarDriverUnload;

  return STATUS_SUCCESS;
}

/*
 * Driver Unload Routine
 */
void StarDriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);

  DbgPrint("S.T.A.R. Driver Unloaded\n");
}
