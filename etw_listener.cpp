#include "etw_listener.h"
#include "hh_scanner.h"
#include <winmeta.h>
#include <string>
#include "util/process_util.h"

#if (_MSC_VER >= 1900)

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


inline std::wstring getProcessName(DWORD pid)
{
    WCHAR processName[MAX_PATH] = { 0 };
    if (!process_util::get_process_path(pid, processName, MAX_PATH * 2)) {
        return L"";
    }
    std::wstring pName(processName);
    std::transform(pName.begin(), pName.end(), pName.begin(), tolower);
    std::size_t found = pName.find_last_of(L"/\\");
    if (found == (-1) || found >= pName.length()) {
        return pName;
    }
    return pName.substr(found + 1);
}


bool isWatchedPid(DWORD pid)
{
    if (!g_hh_args.names_list.size() && !g_hh_args.pids_list.size()) {
        // no filter applied, watch everything
        return true;
    }
    if (g_hh_args.pids_list.find(pid) != g_hh_args.pids_list.end()) {
        // the PID is on the watch list
        return true;
    }
    
    // get process name:
    std::wstring wImgFileName = getProcessName(pid);
    if (g_hh_args.names_list.find(wImgFileName) != g_hh_args.names_list.end()) {
        // the name is on the watch list
        return true;
    }
    // the PID is not on the watch list
    return false;
}

bool isWatchedName(std::string& imgFileName)
{
    if (!g_hh_args.names_list.size() && !g_hh_args.pids_list.size()) {
        // no filter applied, watch everything
        return true;
    }
    std::wstring wImgFileName(imgFileName.begin(), imgFileName.end());
    if (g_hh_args.names_list.find(wImgFileName) != g_hh_args.names_list.end()) {
        // the name is on the watch list
        return true;
    }
    // the name is not on the watch list
    return false;
}

void runHHScan(std::uint32_t pid)
{
    // local copy of arguments
    t_hh_params args = g_hh_args;

    // during the current scan use only a single PID
    args.pids_list.clear();
    args.names_list.clear();
    args.pids_list.insert(pid);
    args.pesieve_args.pid = pid;

    HHScanner hhunter(args);
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
    krabs::kernel::image_load_provider      imageLoadProvider;
    krabs::kernel::virtual_alloc_provider   virtualAllocProvider;
    krabs::kernel::network_tcpip_provider   tcpIpProvider;
    krabs::kernel::object_manager_provider  objectMgrProvider;

    // Process Start Trigger
    processProvider.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context)
        {
            krabs::schema schema(record, trace_context.schema_locator);
            if (schema.event_opcode() == WINEVENT_OPCODE_START)
            {
                krabs::parser parser(schema);
                std::string filename = parser.parse<std::string>(L"ImageFileName");
                if (!isWatchedName(filename)) return;

                std::uint32_t pid = parser.parse<std::uint32_t>(L"ProcessId");
                // New process reset cooldown just in case
                resetCooldown(pid);

                std::cout << std::dec << time(NULL) << " : New Process: " << filename << " (" << pid << ")" << std::endl;
                
            }
        });

    imageLoadProvider.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context)
        {
            krabs::schema schema(record, trace_context.schema_locator);
            if (schema.event_opcode() == 10) { // Load
                krabs::parser parser(schema);
                std::uint32_t pid = parser.parse<std::uint32_t>(L"ProcessId");
                if (!isWatchedPid(pid)) return;

                std::wstring filename = parser.parse<std::wstring>(L"FileName");
                std::uint8_t sign = parser.parse<std::uint8_t>(L"SignatureType");
                
                std::wcout << std::dec << pid << " : " << time(NULL) << " : IMAGE:" << filename << " : " << sign << std::endl;
                //runHHScan(pid);
                //std::wcout << std::dec << pid << ": IMAGE:" << schema.task_name() << " : Opcode : " << schema.opcode_name() << " : " << std::dec << schema.event_opcode() << "\n";
                /*for (krabs::property& prop : parser.properties())
                {
                    std::wcout << prop.name() << "\n";
                }*/
            }
        });

    tcpIpProvider.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context)
        {
            krabs::schema schema(record, trace_context.schema_locator);
            krabs::parser parser(schema);
            std::uint32_t pid = parser.parse<std::uint32_t>(L"PID");
            if (!isWatchedPid(pid)) return;

            std::wcout << std::dec << pid << ": TCPIP:" << schema.task_name() << " : Opcode : " << schema.opcode_name() << " : " << std::dec << schema.event_opcode() << "\n";
            /*for (krabs::property& prop : parser.properties())
            {
                std::wcout << prop.name() << "\n";
            }*/
            runHHScan(pid);
        });


    objectMgrProvider.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context)
        {
            krabs::schema schema(record, trace_context.schema_locator);
            if (schema.event_opcode() != 32 && schema.event_opcode() != 33) // CreateHandle, CloseHandle
            {
                krabs::parser parser(schema);
                std::wcout << "ObjManager:" << schema.task_name() << " : Opcode : " << schema.opcode_name() << " : " << std::dec << schema.event_opcode() << "\n";
                for (krabs::property& prop : parser.properties())
                {
                    std::wcout << prop.name() << "\n";
                }
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

                if (!isWatchedPid(targetPid)) return;

                if (!isCooldown(targetPid))
                    return;

                bool doScan = false;
                LPVOID baseAddress = parser.parse<LPVOID>(L"BaseAddress");

                if (targetPid)
                {
                    doScan = isAllocationExecutable(targetPid, baseAddress);
                }

                if (doScan)
                {
                    updateCooldown(targetPid);
                    runHHScan(targetPid);
                }
            }
        });

    bool isOk = true;
    trace.enable(tcpIpProvider);
    trace.enable(objectMgrProvider);
    //trace.enable(processProvider);
    //trace.enable(imageLoadProvider);
    //trace.enable(virtualAllocProvider);
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

#endif //(_MSC_VER >= 1900)
