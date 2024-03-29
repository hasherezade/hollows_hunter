#include "etw_listener.h"
#include "hh_scanner.h"

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
    if (hProcess)
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

        } while (stop == FALSE && isExec == FALSE);

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
