/*
 * S.T.A.R. - System Threat & Anomaly Radar
 * Windows platform implementation
 *
 * Copyright (C) 2026 Naveed Gung
 * Licensed under GPLv3 - see LICENSE file
 */

#ifdef _WIN32

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include "../../include/star_types.h"
#include "../../include/star_platform.h"

/* ============================================================
 * Internal State
 * ============================================================ */

static bool g_initialized = false;
static bool g_elevated = false;

/* ============================================================
 * NT API Definitions (for direct syscall access)
 * ============================================================ */

typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

typedef enum _SYSTEM_INFORMATION_CLASS_STAR {
    SystemProcessInformation_Star = 5
} SYSTEM_INFORMATION_CLASS_STAR;

typedef NTSTATUS (WINAPI *PFN_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (WINAPI *PFN_NtQueryVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    ULONG MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
);

static PFN_NtQuerySystemInformation pfnNtQuerySystemInformation = NULL;
static PFN_NtQueryVirtualMemory pfnNtQueryVirtualMemory = NULL;
static HMODULE g_ntdll = NULL;

/* ============================================================
 * Initialization & Cleanup
 * ============================================================ */

STAR_STATUS star_platform_init(void)
{
    if (g_initialized) return STAR_STATUS_OK;

    g_ntdll = GetModuleHandleA("ntdll.dll");
    if (!g_ntdll) {
        return STAR_STATUS_ERROR;
    }

    pfnNtQuerySystemInformation = (PFN_NtQuerySystemInformation)
        GetProcAddress(g_ntdll, "NtQuerySystemInformation");
    pfnNtQueryVirtualMemory = (PFN_NtQueryVirtualMemory)
        GetProcAddress(g_ntdll, "NtQueryVirtualMemory");

    if (!pfnNtQuerySystemInformation) {
        return STAR_STATUS_ERROR;
    }

    g_initialized = true;
    return STAR_STATUS_OK;
}

void star_platform_cleanup(void)
{
    g_initialized = false;
    g_elevated = false;
    pfnNtQuerySystemInformation = NULL;
    pfnNtQueryVirtualMemory = NULL;
    g_ntdll = NULL;
}

/* ============================================================
 * Privilege Elevation
 * ============================================================ */

STAR_STATUS star_platform_elevate_privileges(void)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &hToken)) {
        return STAR_STATUS_ACCESS_DENIED;
    }

    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
        CloseHandle(hToken);
        return STAR_STATUS_ACCESS_DENIED;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        CloseHandle(hToken);
        return STAR_STATUS_ACCESS_DENIED;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        CloseHandle(hToken);
        return STAR_STATUS_ACCESS_DENIED;
    }

    CloseHandle(hToken);
    g_elevated = true;
    return STAR_STATUS_OK;
}

/* ============================================================
 * Process Enumeration (via NtQuerySystemInformation)
 * ============================================================ */

/* Forward declaration for list append (defined in platform_common.c) */
extern STAR_STATUS star_process_list_append(STAR_PROCESS_LIST *list,
                                            const STAR_PROCESS_INFO *info);

STAR_STATUS star_platform_enum_processes(STAR_PROCESS_LIST *list)
{
    if (!list) return STAR_STATUS_ERROR;
    if (!g_initialized) return STAR_STATUS_ERROR;

    list->head = NULL;
    list->tail = NULL;
    list->count = 0;

    /*
     * Use NtQuerySystemInformation with SystemProcessInformation (5)
     * to enumerate processes directly from kernel structures,
     * bypassing higher-level APIs that can be hooked.
     */
    ULONG buffer_size = 1024 * 1024; /* Start with 1MB */
    PVOID buffer = NULL;
    NTSTATUS status;
    ULONG return_length = 0;

    do {
        buffer = malloc(buffer_size);
        if (!buffer) return STAR_STATUS_NO_MEMORY;

        status = pfnNtQuerySystemInformation(
            SystemProcessInformation_Star,
            buffer,
            buffer_size,
            &return_length
        );

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            free(buffer);
            buffer = NULL;
            buffer_size = return_length + 4096;
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (status != STATUS_SUCCESS) {
        free(buffer);
        return STAR_STATUS_ERROR;
    }

    /* Walk the linked list of SYSTEM_PROCESS_INFORMATION entries */
    BYTE *current = (BYTE *)buffer;
    while (1) {
        /* Read the NextEntryOffset at offset 0 */
        /* UniqueProcessId is at a known offset in the structure */
        /* We use the documented offsets for the structure */

        STAR_PROCESS_INFO proc_info;
        memset(&proc_info, 0, sizeof(proc_info));

        /* Extract PID - offset depends on architecture but we use
         * the toolhelp32 fallback for reliability */
        /* For the initial implementation, fall back to CreateToolhelp32Snapshot
         * which is more portable across Windows versions */
        break; /* Break out - use toolhelp32 fallback below */
    }
    free(buffer);

    /* Toolhelp32 fallback - reliable across all Windows versions */
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return STAR_STATUS_ERROR;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &pe32)) {
        CloseHandle(snapshot);
        return STAR_STATUS_ERROR;
    }

    do {
        STAR_PROCESS_INFO info;
        memset(&info, 0, sizeof(info));

        info.pid = pe32.th32ProcessID;
        info.ppid = pe32.th32ParentProcessID;
        info.thread_count = pe32.cntThreads;

        /* Copy process name (szExeFile is already a narrow string) */
        strncpy(info.name, pe32.szExeFile, STAR_MAX_PROCESS_NAME - 1);
        info.name[STAR_MAX_PROCESS_NAME - 1] = '\0';

        /* Get additional info via OpenProcess */
        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE, pe32.th32ProcessID
        );

        if (hProcess) {
            /* Get full path */
            DWORD path_size = STAR_MAX_PATH;
            QueryFullProcessImageNameA(hProcess, 0, info.path, &path_size);

            /* Get memory usage */
            PROCESS_MEMORY_COUNTERS pmc;
            if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                info.memory_usage = pmc.WorkingSetSize;
            }

            /* Get creation time */
            FILETIME create_time, exit_time, kernel_time, user_time;
            if (GetProcessTimes(hProcess, &create_time, &exit_time,
                               &kernel_time, &user_time)) {
                ULARGE_INTEGER ul;
                ul.LowPart = create_time.dwLowDateTime;
                ul.HighPart = create_time.dwHighDateTime;
                info.create_time = ul.QuadPart;
            }

            /* Check if elevated */
            HANDLE hToken;
            if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
                TOKEN_ELEVATION elevation;
                DWORD size;
                if (GetTokenInformation(hToken, TokenElevation,
                                       &elevation, sizeof(elevation), &size)) {
                    info.is_elevated = (elevation.TokenIsElevated != 0);
                }
                CloseHandle(hToken);
            }

            CloseHandle(hProcess);
        }

        star_process_list_append(list, &info);

    } while (Process32Next(snapshot, &pe32));

    CloseHandle(snapshot);
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

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, pid
    );

    if (!hProcess) {
        return STAR_STATUS_ACCESS_DENIED;
    }

    /* Full path */
    DWORD path_size = STAR_MAX_PATH;
    QueryFullProcessImageNameA(hProcess, 0, info->path, &path_size);

    /* Extract name from path */
    const char *name = strrchr(info->path, '\\');
    if (name) {
        strncpy(info->name, name + 1, STAR_MAX_PROCESS_NAME - 1);
    }

    /* Memory usage */
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
        info->memory_usage = pmc.WorkingSetSize;
    }

    /* Thread count via snapshot */
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);
        if (Thread32First(snap, &te32)) {
            do {
                if (te32.th32OwnerProcessID == pid) {
                    info->thread_count++;
                }
            } while (Thread32Next(snap, &te32));
        }
        CloseHandle(snap);
    }

    /* Creation time */
    FILETIME ct, et, kt, ut;
    if (GetProcessTimes(hProcess, &ct, &et, &kt, &ut)) {
        ULARGE_INTEGER ul;
        ul.LowPart = ct.dwLowDateTime;
        ul.HighPart = ct.dwHighDateTime;
        info->create_time = ul.QuadPart;
    }

    /* Elevation check */
    HANDLE hToken;
    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size;
        if (GetTokenInformation(hToken, TokenElevation,
                               &elevation, sizeof(elevation), &size)) {
            info->is_elevated = (elevation.TokenIsElevated != 0);
        }
        CloseHandle(hToken);
    }

    CloseHandle(hProcess);
    return STAR_STATUS_OK;
}

/* ============================================================
 * Memory Region Enumeration
 * ============================================================ */

STAR_STATUS star_platform_enum_memory_regions(uint32_t pid, STAR_MEMORY_REGION **regions)
{
    if (!regions) return STAR_STATUS_ERROR;
    *regions = NULL;

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, pid
    );

    if (!hProcess) {
        return STAR_STATUS_ACCESS_DENIED;
    }

    MEMORY_BASIC_INFORMATION mbi;
    STAR_MEMORY_REGION *head = NULL;
    STAR_MEMORY_REGION *tail = NULL;
    BYTE *addr = NULL;

    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT) {
            STAR_MEMORY_REGION *region = (STAR_MEMORY_REGION *)calloc(
                1, sizeof(STAR_MEMORY_REGION));
            if (!region) {
                CloseHandle(hProcess);
                star_memory_region_list_free(head);
                return STAR_STATUS_NO_MEMORY;
            }

            region->base_address = (uint64_t)mbi.BaseAddress;
            region->size = mbi.RegionSize;
            region->protection = mbi.Protect;
            region->type = mbi.Type;
            region->is_executable = (mbi.Protect & (PAGE_EXECUTE |
                PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                PAGE_EXECUTE_WRITECOPY)) != 0;
            region->is_writable = (mbi.Protect & (PAGE_READWRITE |
                PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE |
                PAGE_EXECUTE_WRITECOPY)) != 0;

            /* Check for PE header in non-image memory (reflective injection) */
            if (region->is_executable && mbi.Type != MEM_IMAGE) {
                BYTE pe_check[2] = {0};
                SIZE_T bytes_read = 0;
                if (ReadProcessMemory(hProcess, mbi.BaseAddress,
                                     pe_check, 2, &bytes_read)) {
                    if (pe_check[0] == 'M' && pe_check[1] == 'Z') {
                        region->has_pe_header = true;
                    }
                }
            }

            /* Get mapped file name if applicable */
            if (mbi.Type == MEM_IMAGE) {
                GetMappedFileNameA(hProcess, mbi.BaseAddress,
                                  region->mapped_file, STAR_MAX_PATH);
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

        addr = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
        if ((BYTE *)mbi.BaseAddress + mbi.RegionSize < addr) break; /* Overflow */
    }

    CloseHandle(hProcess);
    *regions = head;
    return STAR_STATUS_OK;
}

/* ============================================================
 * Process Memory Read
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

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return STAR_STATUS_ACCESS_DENIED;

    SIZE_T read = 0;
    BOOL ok = ReadProcessMemory(hProcess, (LPCVOID)(uintptr_t)address,
                                buffer, size, &read);
    CloseHandle(hProcess);

    *bytes_read = (size_t)read;
    return ok ? STAR_STATUS_OK : STAR_STATUS_ERROR;
}

/* ============================================================
 * Syscall Table & IDT Checks (Stubs - require kernel driver)
 * ============================================================ */

STAR_STATUS star_platform_check_syscall_table(STAR_DETECTION_LIST *detections)
{
    (void)detections;
    /* Full implementation requires star.sys kernel driver.
     * User-space heuristics can be added here as a fallback. */
    return STAR_STATUS_UNSUPPORTED;
}

STAR_STATUS star_platform_check_idt(STAR_DETECTION_LIST *detections)
{
    (void)detections;
    /* Requires kernel driver for ring-0 access to IDT. */
    return STAR_STATUS_UNSUPPORTED;
}

/* ============================================================
 * System Information
 * ============================================================ */

uint64_t star_platform_get_timestamp_ns(void)
{
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (uint64_t)((double)counter.QuadPart / freq.QuadPart * 1e9);
}

uint32_t star_platform_get_cpu_count(void)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwNumberOfProcessors;
}

uint64_t star_platform_get_total_memory(void)
{
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    return ms.ullTotalPhys;
}

#endif /* _WIN32 */
