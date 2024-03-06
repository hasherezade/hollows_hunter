// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example shows how to use a UserTrace to the monitor Microsoft-Windows-Security-Auditing events
// that populate the Security EventLog.
// This is a special case due to additional security on this provider.

using System;
using System.Security.Principal;
using Microsoft.O365.Security.ETW;

namespace ManagedExamples
{
    public static class UserTrace005
    {
        public static void Start()
        {
            // While Adminstrator is sufficent to view the Security EventLog,
            // SYSTEM is required for the Microsoft-Windows-Security-Auditing provider.
            if (!WindowsIdentity.GetCurrent().IsSystem)
            {
                Console.WriteLine("Microsoft-Windows-Security-Auditing can only be traced by SYSTEM");
                return;
            }

            // Further, only one trace session is allowed for this provider.
            // This session is created by the OS and is called 'EventLog-Security'.
            // We can't Stop this session, but we can Open a handle to it.
            var trace = new UserTrace("EventLog-Security");
            var provider = new Provider("Microsoft-Windows-Security-Auditing");

            // We also can't modify the flags of the trace session.
            // This will silently fail.
            provider.Any = Provider.AllBitsSet;

            // But we can receive events - but only those configured by the audit policy.
            // e.g. to enable event 4703 run -> auditpol /set /subcategory:"Token Right Adjusted Events"
            provider.OnEvent += (record) =>
            {
                Console.WriteLine($"Event {record.Id}({record.Name}) received.");

                if (record.Id == 4703) // "A user right was adjusted."
                {
                    var enabledPrivilegeList = record.GetUnicodeString("EnabledPrivilegeList", "");
                    var disabledPrivilegeList = record.GetUnicodeString("DisabledPrivilegeList", "");

                    Console.WriteLine($"\tEnabledPrivilegeList={enabledPrivilegeList}");
                    Console.WriteLine($"\tDisabledPrivilegeList={disabledPrivilegeList}");
                }
            };

            trace.Enable(provider);

            trace.Start();
        }
    }
}
