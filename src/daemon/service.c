/*
 * S.T.A.R. - System Threat & Anomaly Radar
 * Windows Service Implementation
 *
 * Copyright (C) 2026 Naveed Gung
 * Licensed under GPLv3 - see LICENSE file
 */

#include "service.h"
#include "daemon_core.h"
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>

#define SERVICE_NAME "StarDaemon"
#define SERVICE_DISPLAY_NAME "S.T.A.R. Threat Detection Service"

SERVICE_STATUS g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE g_ServiceStopEvent = NULL;

void WINAPI ServiceCtrlHandler(DWORD dwControl) {
  switch (dwControl) {
  case SERVICE_CONTROL_STOP:
  case SERVICE_CONTROL_SHUTDOWN:
    g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    /* Signal the daemon core to stop */
    star_daemon_stop_signal();
    SetEvent(g_ServiceStopEvent);
    break;
  default:
    break;
  }
}

void WINAPI ServiceMain(DWORD argc, LPTSTR *argv) {
  (void)argc;
  (void)argv;

  g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);
  if (!g_StatusHandle) {
    return;
  }

  g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
  g_ServiceStatus.dwControlsAccepted =
      SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
  g_ServiceStatus.dwWin32ExitCode = 0;
  g_ServiceStatus.dwServiceSpecificExitCode = 0;
  g_ServiceStatus.dwCheckPoint = 0;

  SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

  g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
  if (!g_ServiceStopEvent) {
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    g_ServiceStatus.dwWin32ExitCode = GetLastError();
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    return;
  }

  g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
  SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

  /* Run the main daemon loop */
  star_daemon_main_loop(false); /* false = service mode */

  g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
  SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

  CloseHandle(g_ServiceStopEvent);
}

int star_service_start(void) {
  SERVICE_TABLE_ENTRY ServiceTable[] = {
      {SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain}, {NULL, NULL}};

  if (StartServiceCtrlDispatcher(ServiceTable) == FALSE) {
    return GetLastError();
  }
  return 0;
}

int star_service_install(void) {
  SC_HANDLE hSCManager;
  SC_HANDLE hService;
  char path[MAX_PATH];

  if (!GetModuleFileName(NULL, path, MAX_PATH)) {
    printf("Cannot get module file name\n");
    return 1;
  }

  hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
  if (!hSCManager) {
    printf("OpenSCManager failed (%lu)\n", GetLastError());
    return 1;
  }

  hService = CreateService(hSCManager, SERVICE_NAME, SERVICE_DISPLAY_NAME,
                           SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                           SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, path,
                           NULL, NULL, NULL, NULL, NULL);

  if (!hService) {
    printf("CreateService failed (%lu)\n", GetLastError());
    CloseServiceHandle(hSCManager);
    return 1;
  }

  printf("Service installed successfully\n");
  CloseServiceHandle(hService);
  CloseServiceHandle(hSCManager);
  return 0;
}

int star_service_uninstall(void) {
  SC_HANDLE hSCManager;
  SC_HANDLE hService;

  hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
  if (!hSCManager) {
    printf("OpenSCManager failed (%lu)\n", GetLastError());
    return 1;
  }

  hService = OpenService(hSCManager, SERVICE_NAME, DELETE);
  if (!hService) {
    printf("OpenService failed (%lu)\n", GetLastError());
    CloseServiceHandle(hSCManager);
    return 1;
  }

  if (!DeleteService(hService)) {
    printf("DeleteService failed (%lu)\n", GetLastError());
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return 1;
  }

  printf("Service uninstalled successfully\n");
  CloseServiceHandle(hService);
  CloseServiceHandle(hSCManager);
  return 0;
}

#else
/* Linux / Other platforms stub */
int star_service_start(void) { return 0; }
int star_service_install(void) { return 0; }
int star_service_uninstall(void) { return 0; }
#endif
