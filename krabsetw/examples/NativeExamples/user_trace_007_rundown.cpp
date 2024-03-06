// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example demonstrates rundown events that capture system state.

#include <iostream>

#include "..\..\krabs\krabs.hpp"
#include "examples.h"

void user_trace_007_rundown::start()
{
    krabs::user_trace trace(L"user_trace_007");

    // Rundown events are not true real-time tracing events. Instead they describe the state
    // of the system - either at the start or end of a trace.

    // Usually these are just extra events in the provider. For example, Microsoft-Windows-Kernel-Process
    // has ProcessRundown events as well as ProcessStart events.
    krabs::provider<> process_provider(L"Microsoft-Windows-Kernel-Process");
    process_provider.any(0x10);  // WINEVENT_KEYWORD_PROCESS
    // ...but the rundown events often cannot be enabled by keyword alone.
    // The trace needs to be sent EVENT_CONTROL_CODE_CAPTURE_STATE.
    // This is what enable_rundown_events() does.
    process_provider.enable_rundown_events();

    auto process_callback = [](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        krabs::parser parser(schema);
        uint32_t pid = parser.parse<uint32_t>(L"ProcessID");
        std::wstring image_name = parser.parse<std::wstring>(L"ImageName");
        std::wcout << schema.provider_name();
        std::wcout << L" task_name=" << schema.task_name();
        std::wcout << L" ProcessID=" << pid;
        std::wcout << L" ImageName=" << image_name;
        std::wcout << std::endl;
    };

    // real-time process start events
    krabs::event_filter process_filter(krabs::predicates::id_is(1));  // ProcessStart
    process_filter.add_on_event_callback(process_callback);
    process_provider.add_filter(process_filter);

    // process rundown events - i.e. running processes
    krabs::event_filter process_rundown_filter(krabs::predicates::id_is(15));  // ProcessRundown
    process_rundown_filter.add_on_event_callback(process_callback);
    process_provider.add_filter(process_rundown_filter);
    
    trace.enable(process_provider);

    
    // Some providers don't follow this pattern and instead split this functionality
    // into a seperate provider. For example, Microsoft-Windows-DotNETRuntime and
    // Microsoft-Windows-DotNETRuntimeRundown.
    krabs::provider<> dotnet_provider(L"Microsoft-Windows-DotNETRuntime");
    krabs::provider<> dotnet_rundown_provider(L"Microsoft-Windows-DotNETRuntimeRundown");

    auto assembly_callback = [](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        krabs::parser parser(schema);
        std::wstring assembly_name = parser.parse<std::wstring>(L"FullyQualifiedAssemblyName");
        std::wcout << schema.provider_name();
        std::wcout << L" opcode_name=" << schema.opcode_name();
        std::wcout << L" ProcessId=" << record.EventHeader.ProcessId;
        std::wcout << L" FullyQualifiedAssemblyName=" << assembly_name;
        std::wcout << std::endl;
    };
    
    // real-time assembly load events
    dotnet_provider.any(0x8);  // LoaderKeyword
    krabs::event_filter assembly_filter(krabs::predicates::id_is(154));  // LoaderAssemblyLoad
    assembly_filter.add_on_event_callback(assembly_callback);
    dotnet_provider.add_filter(assembly_filter);
    trace.enable(dotnet_provider);
    
    // assembly rundown events - i.e. loaded assemblies
    // Note - use StartRundownKeyword / EndRundownKeyword to control whether the state is enumerated
    // at the start or the end of the trace.
    dotnet_rundown_provider.any(0x8 |   // LoaderRundownKeyword
                                0x40);  // StartRundownKeyword
    krabs::event_filter assembly_rundown_filter(krabs::predicates::id_is(155));  // LoaderAssemblyDCStart
    assembly_rundown_filter.add_on_event_callback(assembly_callback);
    dotnet_rundown_provider.add_filter(assembly_rundown_filter);
    trace.enable(dotnet_rundown_provider);

    trace.start();
}