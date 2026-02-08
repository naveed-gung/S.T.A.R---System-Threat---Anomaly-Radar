/*
 * S.T.A.R. - System Threat & Anomaly Radar
 * IPC Implementation (Windows Named Pipes)
 *
 * Copyright (C) 2026 Naveed Gung
 * Licensed under GPLv3 - see LICENSE file
 */

#include "ipc.h"
#include <process.h>
#include <stdio.h>
#include <windows.h>


#define PIPE_NAME "\\\\.\\pipe\\star_daemon"
#define BUFFER_SIZE 4096

static HANDLE g_hPipe = INVALID_HANDLE_VALUE;
static HANDLE g_hThread = NULL;
static volatile bool g_running = false;
static volatile bool g_client_connected = false;

/* Lock for thread safety */
static CRITICAL_SECTION g_cs;

/* Thread function to handle connections */
static unsigned __stdcall ipc_thread(void *arg) {
  (void)arg;

  while (g_running) {
    if (g_hPipe == INVALID_HANDLE_VALUE) {
      /* Create the named pipe */
      g_hPipe = CreateNamedPipeA(
          PIPE_NAME, PIPE_ACCESS_DUPLEX,
          PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
          1,           /* Max instances */
          BUFFER_SIZE, /* Out buffer */
          BUFFER_SIZE, /* In buffer */
          0,           /* Default timeout */
          NULL         /* Security attributes */
      );

      if (g_hPipe == INVALID_HANDLE_VALUE) {
        /* Retry after delay */
        Sleep(1000);
        continue;
      }
    }

    /* Wait for client connection */
    /* Note: This blocks until client connects or pipe is closed */
    BOOL connected = ConnectNamedPipe(g_hPipe, NULL)
                         ? TRUE
                         : (GetLastError() == ERROR_PIPE_CONNECTED);

    if (connected && g_running) {
      EnterCriticalSection(&g_cs);
      g_client_connected = true;
      LeaveCriticalSection(&g_cs);

      /* Wait until client disconnects */
      /* In a real implementation, we'd read commands here */
      BYTE buffer[BUFFER_SIZE];
      DWORD bytes_read;

      while (g_running &&
             ReadFile(g_hPipe, buffer, BUFFER_SIZE, &bytes_read, NULL)) {
        /* Process commands from UI if needed */
      }

      /* Client disconnected */
      EnterCriticalSection(&g_cs);
      g_client_connected = false;
      LeaveCriticalSection(&g_cs);

      DisconnectNamedPipe(g_hPipe);
    } else {
      /* Connection failed or aborted */
      CloseHandle(g_hPipe);
      g_hPipe = INVALID_HANDLE_VALUE;
    }
  }

  return 0;
}

STAR_STATUS star_ipc_init(void) {
  InitializeCriticalSection(&g_cs);
  g_running = true;

  uintptr_t thread_handle = _beginthreadex(NULL, 0, ipc_thread, NULL, 0, NULL);
  if (thread_handle == 0) {
    return STAR_STATUS_ERROR;
  }

  g_hThread = (HANDLE)thread_handle;
  return STAR_STATUS_OK;
}

void star_ipc_shutdown(void) {
  g_running = false;

  /* Cancel blocking I/O if possible or connect dummy client to unblock */
  /* For simplicity, we just close handle and wait poorly */
  if (g_hPipe != INVALID_HANDLE_VALUE) {
    CloseHandle(
        g_hPipe); /* This might unblock ConnectNamedPipe depending on flags */
    g_hPipe = INVALID_HANDLE_VALUE;
  }

  if (g_hThread) {
    WaitForSingleObject(g_hThread, 1000);
    CloseHandle(g_hThread);
    g_hThread = NULL;
  }

  DeleteCriticalSection(&g_cs);
}

void star_ipc_broadcast_event(const STAR_DETECTION *detection) {
  if (!detection)
    return;

  EnterCriticalSection(&g_cs);
  if (g_client_connected && g_hPipe != INVALID_HANDLE_VALUE) {
    char buffer[BUFFER_SIZE];
    /* Simple JSON formatting */
    int len = snprintf(buffer, BUFFER_SIZE,
                       "{\"type\":\"detection\",\"score\":%u,\"class\":%d,"
                       "\"type_str\":\"%s\",\"desc\":\"%s\"}\n",
                       detection->threat_score, detection->detection_class,
                       detection->detection_type, detection->description);

    if (len > 0) {
      DWORD written;
      WriteFile(g_hPipe, buffer, len, &written, NULL);
    }
  }
  LeaveCriticalSection(&g_cs);
}

bool star_ipc_is_connected(void) {
  bool connected;
  EnterCriticalSection(&g_cs);
  connected = g_client_connected;
  LeaveCriticalSection(&g_cs);
  return connected;
}
