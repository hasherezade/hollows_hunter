// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example shows how to enable less documented kernel events.

#include <iostream>
#include "..\..\krabs\krabs.hpp"
#include "..\..\krabs\krabs\perfinfo_groupmask.hpp"
#include "examples.h"

void kernel_trace_002::start()
{
    krabs::kernel_trace trace(L"kernel_trace_002");

    // Some kernel providers can't be enabled via EnableFlags and you need to call
    // TraceSetInformation with an extended PERFINFO_GROUPMASK instead.
    // e.g. https://docs.microsoft.com/en-us/windows/win32/etw/obtrace
    // Krabs has convenience providers for some of these, but otherwise the same
    // thing could be done with:
    //    krabs::kernel_provider provider(SOME_GUID, SOME_ULONG_MASK_VALUE);
    krabs::kernel::object_manager_provider ob_provider;
    ob_provider.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        if (record.EventHeader.EventDescriptor.Opcode == 33) {
            krabs::schema schema(record, trace_context.schema_locator);
            krabs::parser parser(schema);
            std::wstring name = parser.parse<std::wstring>(L"ObjectName");
            if (name.length() >= 3 && name.compare(name.length() - 3, 3, L"dll") == 0)
                std::wcout << L"Handle closed for object with name " << name << std::endl;
        }
        });
    trace.enable(ob_provider);

    // You can also set a default callback to handle any events that don't
    // have a corresponding provider registered.
    // This is helpful if you're not yet sure which provider GUID is required for a
    // given EnableFlags or PERFINFO_GROUPMASK. In particualar, the PERFINFO_GROUPMASKs
    // aren't documented by Microsoft so it's useful to have a way to receive those events.
    // So we enable them with any placeholder guid for now. For example -
    krabs::kernel_provider hive_provider(GUID_NULL, PERF_REG_HIVE);
    // In this case, the correct provider GUID (unsurprisingly) turns out to be krabs::guids::registry :-)
    // Though the HiveInit/HiveLink/HiveDirty/Counters events enabled by this aren't documented.
    //
    // You'll also likely receive the EventTrace_Header and any HWConfig events here.
    //  * https://docs.microsoft.com/en-us/windows/win32/etw/eventtrace-header
    //  * https://docs.microsoft.com/en-us/windows/win32/etw/hwconfig
    trace.set_default_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        std::wcout << std::to_wstring(record.EventHeader.ProviderId);
        std::wcout << L" provider=" << schema.provider_name();
        std::wcout << L" event_name=" << schema.event_name();
        std::wcout << L" task_name=" << schema.task_name();
        std::wcout << L" opcode=" << schema.event_opcode();
        std::wcout << L" opcode_name=" << schema.opcode_name();
        std::wcout << std::endl;
        });
    trace.enable(hive_provider);

    trace.start();
}
