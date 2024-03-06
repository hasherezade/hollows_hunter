// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example demonstrates rundown events that capture system state.

using System;
using Microsoft.O365.Security.ETW;

namespace ManagedExamples
{
    public static class UserTrace006_Rundown
    {
        public static void Start()
        {
            var trace = new UserTrace("UserTrace006_Rundown");

            // Rundown events are not true real-time tracing events. Instead they describe the state of the system.

            // Usually these are just extra events in the provider. For example, Microsoft-Windows-Kernel-Process
            // has ProcessRundown events as well as ProcessStart events.
            var provider = new Provider("Microsoft-Windows-Kernel-Process");
            provider.Any = 0x10;  // WINEVENT_KEYWORD_PROCESS
                                  // ...but the rundown events often cannot be enabled by keyword alone.
                                  // The trace needs to be sent EVENT_CONTROL_CODE_CAPTURE_STATE.
                                  // This is what EnableRundownEvents() does.
            provider.EnableRundownEvents();

            // real-time process start events
            var processFilter = new EventFilter(Filter.EventIdIs(1));  // ProcessStart
            processFilter.OnEvent += ProcessEventHandler;
            provider.AddFilter(processFilter);

            // process rundown events - i.e. running processes
            var processRundownFilter = new EventFilter(Filter.EventIdIs(15));  // ProcessRundown
            processRundownFilter.OnEvent += ProcessEventHandler;
            provider.AddFilter(processRundownFilter);

            trace.Enable(provider);
            trace.Start();
        }

        private static void ProcessEventHandler(IEventRecord record)
        {
            var pid = record.GetUInt32("ProcessID");
            var imageName = record.GetUnicodeString("ImageName");
            Console.WriteLine($"{record.TaskName} pid={pid} ImageName={imageName}");
        }
    }
}
