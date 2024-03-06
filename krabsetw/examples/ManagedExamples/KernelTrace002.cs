// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example shows how to enable less documented kernel events.

using System;
using Microsoft.O365.Security.ETW;
using Kernel = Microsoft.O365.Security.ETW.Kernel;

namespace ManagedExamples
{
    public static class KernelTrace002
    {
        public static void Start()
        {
            var trace = new KernelTrace("KernelTrace002");

            // Some kernel providers can't be enabled via EnableFlags and you need to call
            // TraceSetInformation with an extended PERFINFO_GROUPMASK instead.
            // e.g. https://docs.microsoft.com/en-us/windows/win32/etw/obtrace
            // Lobster has convenience providers for some of these, but otherwise the same
            // thing could be done with:
            //    var provider = new KernelProvider(SOME_GUID, SOME_MASK_VALUE);
            var objectManagerProvider = new Kernel.ObjectManagerProvider();
            objectManagerProvider.OnEvent += (record) =>
            {
                if (record.Opcode == 33)
                {
                    var name = record.GetUnicodeString("ObjectName", string.Empty);
                    if (name.EndsWith(".dll"))
                        Console.WriteLine($"Handle closed for object with name {name}");
                }
            };
            trace.Enable(objectManagerProvider);

            // You can also set a default callback to handle any events that don't
            // have a corresponding provider registered.
            // This is helpful if you're not yet sure which provider GUID is required for a
            // given EnableFlags or PERFINFO_GROUPMASK. In particualar, the PERFINFO_GROUPMASKs
            // aren't documented by Microsoft so it's useful to have a way to receive those events.
            // So we enable them with any placeholder guid for now. For example -
            uint PERF_REG_HIVE = 0x41000000;  // from perfinfo_groupmask.hpp
            var hiveProvider = new KernelProvider(Guid.Empty, PERF_REG_HIVE);
            // In this case, the correct provider GUID (unsurprisingly) turns out to be krabs::guids::registry :-)
            // Though the HiveInit/HiveLink/HiveDirty/Counters events enabled aren't documented.
            //
            // You'll also likely receive the EventTrace_Header and any HWConfig events here.
            //  * https://docs.microsoft.com/en-us/windows/win32/etw/eventtrace-header
            //  * https://docs.microsoft.com/en-us/windows/win32/etw/hwconfig
            trace.SetDefaultEventCallback((record) =>
            {
                Console.WriteLine($"{record.ProviderId} provider={record.ProviderName} task_name={record.TaskName} opcode={record.Opcode} opcode_name={record.OpcodeName}");
            });
            trace.Enable(hiveProvider);

            trace.Start();
        }
    }
}
