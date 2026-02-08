/*
 * S.T.A.R. - System Threat & Anomaly Radar
 * Daemon Entry Point
 *
 * Copyright (C) 2026 Naveed Gung
 * Licensed under GPLv3 - see LICENSE file
 */

#include "daemon_core.h"
#include "service.h"
#include <stdio.h>
#include <string.h>


void print_usage(const char *prog_name) {
  printf("S.T.A.R. Daemon\n");
  printf("Usage: %s [command]\n\n", prog_name);
  printf("Commands:\n");
  printf("  --install    Install as Windows Service\n");
  printf("  --uninstall  Uninstall Windows Service\n");
  printf("  --console    Run in console mode (debug)\n");
  printf("  --help       Show this help message\n");
}

int main(int argc, char *argv[]) {
  if (argc > 1) {
    if (strcmp(argv[1], "--install") == 0) {
      return star_service_install();
    } else if (strcmp(argv[1], "--uninstall") == 0) {
      return star_service_uninstall();
    } else if (strcmp(argv[1], "--console") == 0) {
      return star_daemon_main_loop(true); /* true = console mode */
    } else if (strcmp(argv[1], "--help") == 0) {
      print_usage(argv[0]);
      return 0;
    } else {
      printf("Unknown command: %s\n", argv[1]);
      print_usage(argv[0]);
      return 1;
    }
  }

  /* No arguments -> Run as service */
  return star_service_start();
}
