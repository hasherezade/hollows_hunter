// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example shows how to quickly load up a kernel trace that prints out
// a notice whenever a binary image (executable or DLL) is loaded.

using System;
using Microsoft.O365.Security.ETW;
using Kernel = Microsoft.O365.Security.ETW.Kernel;

namespace ManagedExamples
{
    public static class KernelTrace001
    {
        public static void Start()
        {
            // Kernel traces use the KernelTrace class, which looks and acts
            // a lot like the UserTrace class. A strange quirk about kernel
            // ETW traces is that prior to Win8, the trace was required to
            // have a specific name. On machines where this is the case, this
            // name we provide is ignored and the required one is used.
            var trace = new KernelTrace("My trace name");

            // Lobster provides a bunch of convenience providers for kernel
            // traces. The set of providers that are allowed by kernel traces
            // is hardcoded by Windows, and Lobster provides simple objects to
            // represent these. If other providers were enabled without an
            // update to Lobster, the same thing could be achieved with:
            //    var provider = new KernelProvider(SOME_FLAGS_VALUE, SOME_GUID);
            var processProvider = new Kernel.ProcessProvider();

            // Kernel providers accept callbacks and event filters, as user
            // providers do.
            processProvider.OnEvent += (record) =>
            {
                // We consult against the opcode for kernel providers.
                // The opcodes are documented here:
                // https://msdn.microsoft.com/en-us/library/windows/desktop/aa364083(v=vs.85).aspx
                if (record.Opcode == 0x01)
                {
                    var image = record.GetAnsiString("ImageFileName", "Unknown");
                    var pid = record.GetUInt32("ProcessId", 0);
                    Console.WriteLine($"{image} started with PID {pid}");
                }
            };

            // From here, a KernelTrace is indistinguishable from a UserTrace
            // in how it's used.
            trace.Enable(processProvider);

            // Another quirk here is that kernel traces can only be done by
            // administrators. :( :( :(
            trace.Start();
        }
    }
}
