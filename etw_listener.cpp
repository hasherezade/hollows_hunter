#include "etw_listener.h"
#include "hh_scanner.h"
#include <winmeta.h>

#define EXECUTABLE_FLAGS (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
#define MAX_PROCESSES 65536

// Global var for ETW thread
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

    g_hh_args.pesieve_args.pid = pid;
}

void resetCooldown(std::uint32_t pid)
{
    pidCooldown[pid] = 0;
}

bool isCooldown(std::uint32_t pid)
{
    if (pidCooldown[pid])
    {
        time_t now = 0;
        time(&now);

        if (now - pidCooldown[pid] > 1)
            resetCooldown(pid);
        else
            //std::cout << "Skipping scan for: " << pid << "is in cooldown" << std::endl;
            return false;
    }

    return true;
}

void updateCooldown(std::uint32_t pid)
{
    if (pidCooldown[pid])
    {
        time(&pidCooldown[pid]);
    }
}


bool isAllocationExecutable(std::uint32_t pid, LPVOID baseAddress)
{
    bool isExec = false;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION, FALSE, pid);
    if (hProcess)
    {
        bool    stop = false;
        PVOID   base = 0;
        LPVOID  addr = baseAddress;
        MEMORY_BASIC_INFORMATION mbi = { 0 };

        do
        {
            if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) && mbi.AllocationBase)
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
                        isExec = true;
                    }

                    // Move to next block
                    addr = static_cast<char*>(addr) + mbi.RegionSize;
                }
                else
                    stop = true;
            }
            else
                stop = true;

        } while (!stop && !isExec);

        CloseHandle(hProcess);
    }
    return isExec;
}

void runHHScan()
{
    // Initiate HH Scan
    HHScanner hhunter(g_hh_args);
    HHScanReport* report = hhunter.scan();
    if (report)
    {
        hhunter.summarizeScan(report);
        delete report;
    }
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
            if (schema.event_opcode() == WINEVENT_OPCODE_START)
            {
                krabs::parser parser(schema);
                std::string filename = parser.parse<std::string>(L"ImageFileName");
                std::uint32_t pid = parser.parse<std::uint32_t>(L"ProcessId");

                // New process reset cooldown just in case
                resetCooldown(pid);
                setPid(pid);

                std::cout << "Scanning New Process: " << filename << " (" << pid << ")" << std::endl;
                runHHScan();
            }
        });

    // Process VirtualAlloc Trigger
    virtualAllocProvider.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context)
        {
            krabs::schema schema(record, trace_context.schema_locator);
            if (schema.event_opcode() == 98) // VirtualAlloc
            {
                krabs::parser parser(schema);
                std::uint32_t targetPid = parser.parse<std::uint32_t>(L"ProcessId");
                LPVOID baseAddress = parser.parse<LPVOID>(L"BaseAddress");

                bool doScan = false;

                if (!isCooldown(targetPid))
                    return;

                if (targetPid)
                {
                    doScan = isAllocationExecutable(targetPid, baseAddress);
                }

                if (doScan)
                {
                    setPid(targetPid);
                    updateCooldown(targetPid);
                    runHHScan();
                }
            }
        });

    bool isOk = true;
    trace.enable(processProvider);
    trace.enable(virtualAllocProvider);
    try {
        std::cout << "Starting listener..." << std::endl;
        trace.start();
    }
    catch (std::runtime_error& err) {
        std::cerr << "[ERROR] " << err.what() << std::endl;
        isOk = false;
    }
    return isOk;
}
