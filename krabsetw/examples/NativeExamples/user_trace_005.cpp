// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example shows how to use a UserTrace to the monitor Microsoft-Windows-Security-Auditing events 
// that populate the Security EventLog.
// This is a special case due to additional security on this provider.

#include <iostream>
#include "..\..\krabs\krabs.hpp"
#include "examples.h"

void user_trace_005::start()
{
    // While Adminstrator is sufficent to view the Security EventLog,
    // SYSTEM is required for the Microsoft-Windows-Security-Auditing provider.
    char user_name[128] = { 0 };
    DWORD user_name_length = 128;
    if (!GetUserNameA(user_name, &user_name_length) || !strcmp(user_name, "SYSTEM") == 0)
    {
        std::wcout << L"Microsoft-Windows-Security-Auditing can only be traced by SYSTEM" << std::endl;
        return;
    }

    // Further, only one trace session is allowed for this provider.
    // This session is created by the OS and is called 'EventLog-Security'.
    // We can't stop() this session, but we can open() a handle to it.
    krabs::user_trace trace(L"EventLog-Security");
    krabs::provider<> provider(L"Microsoft-Windows-Security-Auditing");

    // We also can't modify the flags of the trace session.
    // This will silently fail.
    provider.any((ULONGLONG)-1);

    // But we can receive events - but only those configured by the audit policy.
    // e.g. to enable event 4703 run -> auditpol /set /subcategory:"Token Right Adjusted Events"
    provider.add_on_event_callback([](const EVENT_RECORD &record, const krabs::trace_context &trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        std::wcout << L"Event " << schema.event_id();
        std::wcout << L"(" << schema.event_name() << L") received." << std::endl;

        if (schema.event_id() == 4703) {  // "A user right was adjusted."
            krabs::parser parser(schema);
            std::wstring enabled_privilege_list = parser.parse<std::wstring>(L"EnabledPrivilegeList");
            std::wstring disabled_privilege_list = parser.parse<std::wstring>(L"DisabledPrivilegeList");

            std::wcout << L"\tEnabledPrivilegeList=" << enabled_privilege_list << std::endl;
            std::wcout << L"\tDisabledPrivilegeList=" << disabled_privilege_list << std::endl;
        }
    });

    trace.enable(provider);

    trace.start();
}
