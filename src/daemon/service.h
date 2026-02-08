/*
 * S.T.A.R. - System Threat & Anomaly Radar
 * Windows Service Header
 *
 * Copyright (C) 2026 Naveed Gung
 * Licensed under GPLv3 - see LICENSE file
 */

#ifndef STAR_SERVICE_H
#define STAR_SERVICE_H

/*
 * Install the service in the SCM.
 */
int star_service_install(void);

/*
 * Uninstall the service from the SCM.
 */
int star_service_uninstall(void);

/*
 * Start the service control dispatcher.
 * (This blocks until the service stops)
 */
int star_service_start(void);

#endif /* STAR_SERVICE_H */
