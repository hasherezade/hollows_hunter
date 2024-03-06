#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <iostream>
#include <limits.h>
#include <string>
#include <map>
#include <vector>

#include <sstream>
#include <WinSock2.h>
#include <windows.h>
#include <time.h>

#include "color_scheme.h"
#include "hh_scanner.h"

#include <pe_sieve_types.h>
#include <pe_sieve_return_codes.h>

#include "params_info/params.h"

#include "util/process_privilege.h"
#include "util/strings_util.h"
#include "hh_ver_short.h"

using namespace hhunter::util;

// ETW includes
#include "krabsetw/krabs/krabs.hpp"

#define EXECUTABLE_FLAGS (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
#define MAX_PROCESSES 65536

void compatibility_alert()
{
    print_in_color(WARNING_COLOR, "[!] Scanner mismatch! For a 64-bit OS, use the 64-bit version of the scanner!\n");
}

// Global var for ETW thread
t_hh_params g_hh_args;
time_t      pidCooldown[MAX_PROCESSES] = { 0 };


// ETW Handler
// To filter our events, we want to compare against the
// event opcode. For kernel traces, you can consult this page
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa364083(v=vs.85).aspx
//
// The documentation specific to the image load provider is here:
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa364068(v=vs.85).aspx

void setPid(std::uint32_t pid)
{
    g_hh_args.pids_list.clear();
    g_hh_args.pids_list.insert(pid);
}

void resetCooldown(std::uint32_t pid)
{
    pidCooldown[pid] = 0;
}

BOOL isCooldown(std::uint32_t pid)
{
    if (0 != pidCooldown[pid])
    {
        time_t now = 0;
        time(&now);

        if (now - pidCooldown[pid] > 1)
            resetCooldown(pid);
        else
            //std::cout << "Skipping scan for: " << pid << "is in cooldown" << std::endl;
            return FALSE;
    }

    return TRUE;
}

void updateCooldown(std::uint32_t pid)
{
    if (0 != pidCooldown[pid])
    {
        time(&pidCooldown[pid]);
    }
}


BOOL isAllocationExecutable(std::uint32_t pid, LPVOID baseAddress)
{
    BOOL isExec = FALSE;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION, FALSE, pid);
    if(hProcess)
    {
        BOOL    stop = FALSE;
        PVOID   base = 0;
        LPVOID  addr = baseAddress;
        MEMORY_BASIC_INFORMATION mbi = { 0 };

        do
        {
            if (NULL != VirtualQueryEx(hProcess, addr, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) && mbi.AllocationBase)
            {
                // Start of the allocation
                if (!base)
                {
                    base = mbi.AllocationBase;
                }

                // Still within?
                if (base == mbi.AllocationBase)
                {
                    if (mbi.AllocationProtect & EXECUTABLE_FLAGS || mbi.Protect & EXECUTABLE_FLAGS)
                    {
                        std::cout << "New Executable Section: " << " (" << pid << ") 0x" << std::hex << addr << " Flags=[Alloc: " << mbi.AllocationProtect << " | Now: " << mbi.Protect << "] " << std::dec << std::endl;
                        isExec = TRUE;
                    }

                    // Move to next block
                    addr = static_cast<char*>(addr) + mbi.RegionSize;
                }
                else
                    stop = TRUE;
            }
            else
                stop = TRUE;

        } while (stop == FALSE && isExec == FALSE );

        CloseHandle(hProcess);
    }

    return isExec;
}

bool ETWstart()
{
    krabs::kernel_trace trace(L"HollowsHunter");

    krabs::kernel::process_provider         processProvider;
    krabs::kernel::virtual_alloc_provider   virtualAllocProvider;

    // Process Start Trigger
    processProvider.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) 
    {
        krabs::schema schema(record, trace_context.schema_locator);

        if (schema.event_opcode() == 1) 
        {
            krabs::parser parser(schema);
            std::string filename = parser.parse<std::string>(L"ImageFileName");
            std::uint32_t pid = parser.parse<std::uint32_t>(L"ProcessId");

            // New process reset cooldown just in case
            resetCooldown(pid);

            std::cout << "Scanning New Process: " << filename << " (" << pid << ")" << std::endl;

            setPid(pid);
            g_hh_args.pesieve_args.pid = pid;
            // Initiate HH Scan
            HHScanner hhunter(g_hh_args);
            HHScanReport* report = hhunter.scan();
            if (report) 
            {
                hhunter.summarizeScan(report);
                delete report;
            }
        }
    });

    // Process VirtualAlloc Trigger
    virtualAllocProvider.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context)
    {
        krabs::schema schema(record, trace_context.schema_locator);

        if (schema.event_opcode() == 98)
        {
            krabs::parser parser(schema);
            std::uint64_t sourcePid = schema.process_id();
            std::uint32_t targetPid = parser.parse<std::uint32_t>(L"ProcessId");
            LPVOID baseAddress = parser.parse<LPVOID>(L"BaseAddress");

            bool doScan = FALSE;

            if (!isCooldown(targetPid))
                return;

            if (0 != targetPid)
            {
                doScan = isAllocationExecutable(targetPid, baseAddress);
            }

            if (doScan)
            {
                setPid(targetPid);
                updateCooldown(targetPid);
                g_hh_args.pesieve_args.pid = targetPid;
                // Initiate HH Scan
                HHScanner hhunter(g_hh_args);
                HHScanReport* report = hhunter.scan();
                if (report)
                {
                    hhunter.summarizeScan(report);
                    delete report;
                }
            }
        }
    });

    bool isOk = true;
    trace.enable(processProvider);
    trace.enable(virtualAllocProvider);
    try {
        std::cout << "Starting listener..." << std::endl;
        trace.start();
        std::cout << "Started" << std::endl;
    }
    catch (std::runtime_error& err) {
        std::cerr << "[ERROR] " << err.what() << std::endl;
        isOk = false;
    }
    return isOk;
}


t_pesieve_res deploy_scan()
{
    t_pesieve_res scan_res = PESIEVE_NOT_DETECTED;
    hhunter::util::set_debug_privilege();
    if (g_hh_args.pesieve_args.data >= pesieve::PE_DATA_SCAN_INACCESSIBLE && g_hh_args.pesieve_args.make_reflection == false) {
        print_in_color(RED, "[WARNING] Scanning of inaccessible pages is enabled only in the reflection mode!\n");
    }
    if (g_hh_args.etw_scan)
    {
        if (!ETWstart()) {
            return PESIEVE_ERROR;
        }
    }
    else
    {
        HHScanner hhunter(g_hh_args);
    do {
        HHScanReport *report = hhunter.scan();
        if (report) {
            hhunter.summarizeScan(report);
            if (report->countSuspicious() > 0) {
                scan_res = PESIEVE_DETECTED;
            }
            delete report;
        }
        if (!HHScanner::isScannerCompatibile()) {
            compatibility_alert();
        }
        } while (g_hh_args.loop_scanning);
    }
    return scan_res;
}

int main(int argc, char *argv[])
{
    hh_args_init(g_hh_args);

    bool info_req = false;
    HHParams uParams(HH_VERSION_STR);
    if (!uParams.parse(argc, argv)) {
        return PESIEVE_INFO;
    }
    uParams.fillStruct(g_hh_args);

    // if scanning of inaccessible pages was requested, auto-enable reflection mode:
    if (g_hh_args.pesieve_args.data == pesieve::PE_DATA_SCAN_INACCESSIBLE || g_hh_args.pesieve_args.data == pesieve::PE_DATA_SCAN_INACCESSIBLE_ONLY) {
        if (!g_hh_args.pesieve_args.make_reflection) {
            g_hh_args.pesieve_args.make_reflection = true;
            print_in_color(RED, "[WARNING] Scanning of inaccessible pages requested: auto-enabled reflection mode!\n");
        }
    }

    print_version(HH_VERSION_STR);
    std::cout << std::endl;
    if (argc < 2) {
        print_in_color(WHITE, "Default scan deployed.");
        std::cout << std::endl;
    }
    const t_pesieve_res  res = deploy_scan();
    uParams.freeStruct(g_hh_args);
    return res;
}
