/*
 * S.T.A.R. - System Threat & Anomaly Radar
 * Linux platform implementation
 *
 * Copyright (C) 2026 Naveed Gung
 * Licensed under GPLv3 - see LICENSE file
 */

#ifdef __linux__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include "../../include/star_types.h"
#include "../../include/star_platform.h"

/* ============================================================
 * Internal State
 * ============================================================ */

static bool g_initialized = false;

/* ============================================================
 * Initialization & Cleanup
 * ============================================================ */

STAR_STATUS star_platform_init(void)
{
    if (g_initialized) return STAR_STATUS_OK;

    /* Verify /proc is mounted */
    struct stat st;
    if (stat("/proc/self/status", &st) != 0) {
        return STAR_STATUS_ERROR;
    }

    g_initialized = true;
    return STAR_STATUS_OK;
}

void star_platform_cleanup(void)
{
    g_initialized = false;
}

/* ============================================================
 * Privilege Elevation
 * ============================================================ */

STAR_STATUS star_platform_elevate_privileges(void)
{
    /* On Linux, we need CAP_SYS_PTRACE or root.
     * Check if we have effective UID 0. */
    if (geteuid() != 0) {
        return STAR_STATUS_ACCESS_DENIED;
    }
    return STAR_STATUS_OK;
}

/* ============================================================
 * Helper: Read a file into a buffer
 * ============================================================ */

static int read_file_contents(const char *path, char *buf, size_t buf_size)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    ssize_t n = read(fd, buf, buf_size - 1);
    close(fd);

    if (n < 0) return -1;
    buf[n] = '\0';
    return (int)n;
}

/* ============================================================
 * Helper: Parse a field from /proc/[pid]/status
 * ============================================================ */

static int parse_status_field(const char *status_buf, const char *field,
                              char *value, size_t value_size)
{
    const char *line = strstr(status_buf, field);
    if (!line) return -1;

    line += strlen(field);
    while (*line == '\t' || *line == ' ') line++;

    size_t i = 0;
    while (*line && *line != '\n' && i < value_size - 1) {
        value[i++] = *line++;
    }
    value[i] = '\0';
    return 0;
}

/* Forward declaration for list append (defined in platform_common.c) */
extern STAR_STATUS star_process_list_append(STAR_PROCESS_LIST *list,
                                            const STAR_PROCESS_INFO *info);

/* ============================================================
 * Process Enumeration (via /proc)
 * ============================================================ */

STAR_STATUS star_platform_enum_processes(STAR_PROCESS_LIST *list)
{
    if (!list) return STAR_STATUS_ERROR;
    if (!g_initialized) return STAR_STATUS_ERROR;

    list->head = NULL;
    list->tail = NULL;
    list->count = 0;

    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) return STAR_STATUS_ERROR;

    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != NULL) {
        /* Only process numeric directories (PIDs) */
        if (!isdigit(entry->d_name[0])) continue;

        uint32_t pid = (uint32_t)atoi(entry->d_name);
        if (pid == 0) continue;

        STAR_PROCESS_INFO info;
        memset(&info, 0, sizeof(info));
        info.pid = pid;

        char path_buf[512];
        char data_buf[4096];

        /* Read /proc/[pid]/status for name, ppid, threads */
        snprintf(path_buf, sizeof(path_buf), "/proc/%u/status", pid);
        if (read_file_contents(path_buf, data_buf, sizeof(data_buf)) > 0) {
            char value[256];

            if (parse_status_field(data_buf, "Name:", value, sizeof(value)) == 0) {
                strncpy(info.name, value, STAR_MAX_PROCESS_NAME - 1);
            }

            if (parse_status_field(data_buf, "PPid:", value, sizeof(value)) == 0) {
                info.ppid = (uint32_t)atoi(value);
            }

            if (parse_status_field(data_buf, "Threads:", value, sizeof(value)) == 0) {
                info.thread_count = (uint32_t)atoi(value);
            }

            /* Check UID for elevation (UID 0 = root) */
            if (parse_status_field(data_buf, "Uid:", value, sizeof(value)) == 0) {
                info.is_elevated = (atoi(value) == 0);
            }

            if (parse_status_field(data_buf, "VmRSS:", value, sizeof(value)) == 0) {
                info.memory_usage = (uint64_t)atoll(value) * 1024; /* kB to bytes */
            }
        }

        /* Read /proc/[pid]/exe symlink for full path */
        snprintf(path_buf, sizeof(path_buf), "/proc/%u/exe", pid);
        ssize_t link_len = readlink(path_buf, info.path, STAR_MAX_PATH - 1);
        if (link_len > 0) {
            info.path[link_len] = '\0';
        }

        /* Read /proc/[pid]/stat for start time */
        snprintf(path_buf, sizeof(path_buf), "/proc/%u/stat", pid);
        if (read_file_contents(path_buf, data_buf, sizeof(data_buf)) > 0) {
            /* Field 22 is starttime (after the comm field in parens) */
            char *close_paren = strrchr(data_buf, ')');
            if (close_paren) {
                unsigned long long starttime = 0;
                /* Skip fields 3-21 to get to field 22 */
                char *p = close_paren + 2;
                for (int i = 0; i < 19 && p; i++) {
                    p = strchr(p, ' ');
                    if (p) p++;
                }
                if (p) {
                    sscanf(p, "%llu", &starttime);
                    info.create_time = starttime;
                }
            }
        }

        /* Detect hidden processes: check if /proc/[pid] is accessible
         * but PID doesn't appear in task list (basic DKOM check) */
        snprintf(path_buf, sizeof(path_buf), "/proc/%u/cmdline", pid);
        struct stat st;
        if (stat(path_buf, &st) != 0 && pid > 1) {
            info.is_hidden = true;
        }

        star_process_list_append(list, &info);
    }

    closedir(proc_dir);
    return STAR_STATUS_OK;
}

/* ============================================================
 * Process Info Query
 * ============================================================ */

STAR_STATUS star_platform_get_process_info(uint32_t pid, STAR_PROCESS_INFO *info)
{
    if (!info) return STAR_STATUS_ERROR;
    if (!g_initialized) return STAR_STATUS_ERROR;

    memset(info, 0, sizeof(STAR_PROCESS_INFO));
    info->pid = pid;

    char path_buf[512];
    char data_buf[4096];

    /* Check if process exists */
    snprintf(path_buf, sizeof(path_buf), "/proc/%u/status", pid);
    if (read_file_contents(path_buf, data_buf, sizeof(data_buf)) < 0) {
        return STAR_STATUS_NOT_FOUND;
    }

    char value[256];
    if (parse_status_field(data_buf, "Name:", value, sizeof(value)) == 0)
        strncpy(info->name, value, STAR_MAX_PROCESS_NAME - 1);
    if (parse_status_field(data_buf, "PPid:", value, sizeof(value)) == 0)
        info->ppid = (uint32_t)atoi(value);
    if (parse_status_field(data_buf, "Threads:", value, sizeof(value)) == 0)
        info->thread_count = (uint32_t)atoi(value);
    if (parse_status_field(data_buf, "Uid:", value, sizeof(value)) == 0)
        info->is_elevated = (atoi(value) == 0);
    if (parse_status_field(data_buf, "VmRSS:", value, sizeof(value)) == 0)
        info->memory_usage = (uint64_t)atoll(value) * 1024;

    snprintf(path_buf, sizeof(path_buf), "/proc/%u/exe", pid);
    ssize_t link_len = readlink(path_buf, info->path, STAR_MAX_PATH - 1);
    if (link_len > 0) info->path[link_len] = '\0';

    return STAR_STATUS_OK;
}

/* ============================================================
 * Memory Region Enumeration (via /proc/[pid]/maps)
 * ============================================================ */

STAR_STATUS star_platform_enum_memory_regions(uint32_t pid, STAR_MEMORY_REGION **regions)
{
    if (!regions) return STAR_STATUS_ERROR;
    *regions = NULL;

    char path_buf[256];
    snprintf(path_buf, sizeof(path_buf), "/proc/%u/maps", pid);

    FILE *fp = fopen(path_buf, "r");
    if (!fp) return STAR_STATUS_ACCESS_DENIED;

    STAR_MEMORY_REGION *head = NULL;
    STAR_MEMORY_REGION *tail = NULL;
    char line[1024];

    while (fgets(line, sizeof(line), fp)) {
        STAR_MEMORY_REGION *region = (STAR_MEMORY_REGION *)calloc(
            1, sizeof(STAR_MEMORY_REGION));
        if (!region) {
            fclose(fp);
            star_memory_region_list_free(head);
            return STAR_STATUS_NO_MEMORY;
        }

        /* Parse: address_start-address_end perms offset dev inode pathname */
        unsigned long long start, end;
        char perms[5] = {0};
        unsigned long long offset;
        char dev[16] = {0};
        unsigned long inode;
        char mapped_path[STAR_MAX_PATH] = {0};

        int fields = sscanf(line, "%llx-%llx %4s %llx %15s %lu %1023[^\n]",
                           &start, &end, perms, &offset, dev, &inode, mapped_path);

        if (fields < 6) {
            free(region);
            continue;
        }

        region->base_address = start;
        region->size = end - start;
        region->is_executable = (perms[2] == 'x');
        region->is_writable = (perms[1] == 'w');

        if (fields >= 7 && mapped_path[0] != '\0') {
            /* Trim leading whitespace */
            char *trimmed = mapped_path;
            while (*trimmed == ' ') trimmed++;
            strncpy(region->mapped_file, trimmed, STAR_MAX_PATH - 1);
        }

        /* Check for ELF header in executable anonymous mappings */
        if (region->is_executable && inode == 0 && mapped_path[0] == '\0') {
            snprintf(path_buf, sizeof(path_buf), "/proc/%u/mem", pid);
            int mem_fd = open(path_buf, O_RDONLY);
            if (mem_fd >= 0) {
                unsigned char elf_check[4] = {0};
                if (pread(mem_fd, elf_check, 4, (off_t)start) == 4) {
                    if (elf_check[0] == 0x7f && elf_check[1] == 'E' &&
                        elf_check[2] == 'L' && elf_check[3] == 'F') {
                        region->has_pe_header = true; /* ELF in anonymous mapping */
                    }
                }
                close(mem_fd);
            }
        }

        region->next = NULL;
        if (!head) {
            head = region;
            tail = region;
        } else {
            tail->next = region;
            tail = region;
        }
    }

    fclose(fp);
    *regions = head;
    return STAR_STATUS_OK;
}

/* ============================================================
 * Process Memory Read (via /proc/[pid]/mem)
 * ============================================================ */

STAR_STATUS star_platform_read_process_memory(
    uint32_t pid,
    uint64_t address,
    void *buffer,
    size_t size,
    size_t *bytes_read)
{
    if (!buffer || !bytes_read) return STAR_STATUS_ERROR;
    *bytes_read = 0;

    char path_buf[256];
    snprintf(path_buf, sizeof(path_buf), "/proc/%u/mem", pid);

    int fd = open(path_buf, O_RDONLY);
    if (fd < 0) return STAR_STATUS_ACCESS_DENIED;

    ssize_t n = pread(fd, buffer, size, (off_t)address);
    close(fd);

    if (n < 0) return STAR_STATUS_ERROR;
    *bytes_read = (size_t)n;
    return STAR_STATUS_OK;
}

/* ============================================================
 * Syscall Table & IDT Checks (Stubs - require kernel module)
 * ============================================================ */

STAR_STATUS star_platform_check_syscall_table(STAR_DETECTION_LIST *detections)
{
    (void)detections;
    /* Full implementation requires star.ko kernel module.
     * User-space can check /proc/kallsyms as a heuristic. */
    return STAR_STATUS_UNSUPPORTED;
}

STAR_STATUS star_platform_check_idt(STAR_DETECTION_LIST *detections)
{
    (void)detections;
    /* Requires kernel module for ring-0 IDT access. */
    return STAR_STATUS_UNSUPPORTED;
}

/* ============================================================
 * System Information
 * ============================================================ */

uint64_t star_platform_get_timestamp_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

uint32_t star_platform_get_cpu_count(void)
{
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return (n > 0) ? (uint32_t)n : 1;
}

uint64_t star_platform_get_total_memory(void)
{
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        return (uint64_t)si.totalram * si.mem_unit;
    }
    return 0;
}

#endif /* __linux__ */
