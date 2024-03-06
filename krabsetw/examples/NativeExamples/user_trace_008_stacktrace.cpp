// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example demonstrates collecting stack traces as part of events.

#include <iostream>

#include "..\..\krabs\krabs.hpp"
#include "examples.h"

void user_trace_008_stacktrace::start()
{
    krabs::user_trace trace(L"user_trace_008_stacktrace");
    krabs::provider<> process_provider(L"Microsoft-Windows-Kernel-Process");
    process_provider.any(0x10);  // WINEVENT_KEYWORD_PROCESS
    process_provider.trace_flags(process_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);

    krabs::event_filter process_filter(krabs::predicates::id_is(1));  // ProcessStart
    process_filter.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        krabs::parser parser(schema);
        auto pid = parser.parse<uint32_t>(L"ProcessID");
        auto image_name = parser.parse<std::wstring>(L"ImageName");
        auto stack_trace = schema.stack_trace();

        std::wcout << std::endl << schema.task_name();
        std::wcout << L" ProcessID=" << pid;
        std::wcout << L" ImageName=" << image_name;
        std::wcout << std::endl << L"Call Stack:" << std::endl;
        for (auto& return_address : stack_trace)
        {
            std::wcout << L"   0x" << std::hex << return_address << std::endl;
        }
        });
    process_provider.add_filter(process_filter);

    trace.enable(process_provider);
    trace.start();
}