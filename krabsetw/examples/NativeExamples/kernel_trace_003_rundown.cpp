// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example shows how to collect kernel rundown events that capture system state.

#include "..\..\krabs\krabs.hpp"
#include "examples.h"
#include <evntrace.h>
#include <iostream>
#include <thread>

#define PRINT_LIMIT 3 // only print a few events for brevity
void process_rundown_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context);
void file_rundown_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context);
void hwconfig_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context);

void kernel_trace_003_rundown::start()
{
    krabs::kernel_trace trace(L"kernel_trace_003_rundown");

    // The kernel provider has a number of events that report system state.

    // Process rundown events - i.e. running processes
    // https://docs.microsoft.com/en-us/windows/win32/etw/process
    // If the EVENT_TRACE_FLAG_PROCESS is enabled -
    // By default, the process provider emits DCStart rundown events at the *start* of the trace.
    // By default, the process provider emits DCEnd rundown events at the *end* of the trace.
    krabs::kernel::process_provider process_provider;
    process_provider.add_on_event_callback(process_rundown_callback);
    trace.enable(process_provider);

    // File rundown events - i.e. open files
    // https://docs.microsoft.com/en-us/windows/win32/etw/fileio
    // If the EVENT_TRACE_FLAG_DISK_FILE_IO is enabled -
    // By default, the process provider emits file rundown events at the *end* of the trace.
    krabs::kernel::disk_file_io_provider fileio_provider;
    fileio_provider.add_on_event_callback(file_rundown_callback);
    trace.enable(fileio_provider);
    
    // Hardware configuration events
    // https://docs.microsoft.com/en-us/windows/win32/etw/hwconfig
    // By default, kernel traces emit these events at the *end* of the trace.
    // No EnableFlags are required.
    krabs::kernel_provider hwconfig_provider(0, krabs::guids::event_trace_config);
    hwconfig_provider.add_on_event_callback(hwconfig_callback);
    trace.enable(hwconfig_provider);

    // We will start and stop a trace to also trigger events that are only emitted at the *end* of a trace.
    std::cout << " - starting trace" << std::endl;
    std::thread thread([&trace]() { trace.start(); });

    // We will wait for all start events to be processed.
    // By default ETW buffers are flush when full, or every second otherwise
    Sleep(1500);

    std::cout << std::endl << " - stopping trace" << std::endl;
    trace.stop();
    thread.join();
 }

void process_rundown_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    static int process_dcstart_count = 0;
    static int process_dcstop_count = 0;

    if (record.EventHeader.EventDescriptor.Opcode == 3 || record.EventHeader.EventDescriptor.Opcode == 4) {
        krabs::schema schema(record, trace_context.schema_locator);
        if ((record.EventHeader.EventDescriptor.Opcode == 3 && process_dcstart_count++ < PRINT_LIMIT) ||
            (record.EventHeader.EventDescriptor.Opcode == 4 && process_dcstop_count++ < PRINT_LIMIT)) {
            std::wcout << schema.task_name() << L"_" << schema.opcode_name();
            std::wcout << L" (" << schema.event_opcode() << L") ";
            krabs::parser parser(schema);
            std::uint32_t pid = parser.parse<std::uint32_t>(L"ProcessId");
            std::wcout << L" ProcessId=" << pid;
            std::string imagefilename = parser.parse<std::string>(L"ImageFileName");
            std::cout << " ImageFileName=" << imagefilename;
            std::wcout << std::endl;
        }

        if (process_dcstart_count == PRINT_LIMIT || process_dcstop_count == PRINT_LIMIT)
            std::wcout << schema.task_name() << L"_" << schema.opcode_name() << L"..." << std::endl;
    }
}

void file_rundown_callback(const EVENT_RECORD & record, const krabs::trace_context & trace_context) {
    static int file_rundown_count = 0;

    if (record.EventHeader.EventDescriptor.Opcode == 36) {  // FileRundown
        krabs::schema schema(record, trace_context.schema_locator);
        if (file_rundown_count++ < PRINT_LIMIT) {
            std::wcout << schema.task_name() << L"_" << schema.opcode_name();
            std::wcout << L" (" << schema.event_opcode() << L") ";
            krabs::parser parser(schema);
            std::wstring filename = parser.parse<std::wstring>(L"FileName");
            std::wcout << L" FileName=" << filename;
            std::wcout << std::endl;
        }

        if (file_rundown_count == PRINT_LIMIT)
            std::wcout << schema.task_name() << L"_" << schema.opcode_name() << L"..." << std::endl;
    }
}

void hwconfig_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    // only return some events for brevity
    if (record.EventHeader.EventDescriptor.Opcode == 10 || // CPU
        record.EventHeader.EventDescriptor.Opcode == 25 || // Platform
        record.EventHeader.EventDescriptor.Opcode == 33 || // DeviceFamily
        record.EventHeader.EventDescriptor.Opcode == 37) { // Boot Config Info
         krabs::schema schema(record, trace_context.schema_locator);
         std::wcout << L"task_name=" << schema.task_name();
         std::wcout << L" opcode=" << schema.event_opcode();
         std::wcout << L" opcode_name=" << schema.opcode_name();
         std::wcout << std::endl;
    }
}
