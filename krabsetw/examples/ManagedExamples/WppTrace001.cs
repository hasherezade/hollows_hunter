// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example shows how to use a UserTrace to monitor WPP providers.
// This is a special case due to slight differences in the event format,
// and the lack of schema information.

using System;
using System.Runtime.InteropServices;
using Microsoft.O365.Security.ETW;

namespace ManagedExamples
{
    public static class WppTrace001
    {
        public static void Start()
        {
            var trace = new UserTrace("WPP_OLE32");

            // WPP providers are basically legacy providers without a registered MOF.
            // They are intended for (internal) debugging purposes only.
            // Note - WPP software tracing has been superceded by TraceLogging.
            //
            // Instead of a manifest or MOF, a separate trace message format (TMF) 
            // file is required to interpret the WPP event data.
            // https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/trace-message-format-file
            //
            // In some cases, the TMF is included in the PDB.
            // https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/tracepdb
            //
            // Otherwise, you can attempt to reconstruct the TMF by hand.
            // https://posts.specterops.io/data-source-analysis-and-dynamic-windows-re-using-wpp-and-tracelogging-e465f8b653f7
            //
            // Luckily, WPP tracing is usually added using Microsoft's convenience macros.
            // And, when you have symbols available, WPP metadata is then fairly straightfoward to extract.
            // https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/adding-wpp-software-tracing-to-a-windows-driver

            // Each WPP trace provider defines a control GUID that uniquely identifies that provider.
            // https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/control-guid
            //
            // The WPP macros generate control GUID globals named "WPP_ThisDir_CTLGUID_<name>"
            //
            // For example, this control GUID is in the symbols for combase.dll
            // WPP_ThisDir_CTLGUID_OLE32 = bda92ae8-9f11-4d49-ba1d-a4c2abca692e
            var ole32WppProvider = new Provider(Guid.Parse("{bda92ae8-9f11-4d49-ba1d-a4c2abca692e}"));

            // In evntrace.h there are ten defined trace levels -
            // TRACE_LEVEL_NONE        0   // Tracing is not on
            // TRACE_LEVEL_CRITICAL    1   // Abnormal exit or termination
            // TRACE_LEVEL_ERROR       2   // Severe errors that need logging
            // TRACE_LEVEL_WARNING     3   // Warnings such as allocation failure
            // TRACE_LEVEL_INFORMATION 4   // Includes non-error cases(e.g.,Entry-Exit)
            // TRACE_LEVEL_VERBOSE     5   // Detailed traces from intermediate steps
            // TRACE_LEVEL_RESERVED6   6
            // TRACE_LEVEL_RESERVED7   7
            // TRACE_LEVEL_RESERVED8   8
            // TRACE_LEVEL_RESERVED9   9
            //
            // Microsoft WPP providers are known to use the reserved levels.
            // Internally, these levels have names like CHATTY, GARRULOUS and LOQUACIOUS.
            //
            // Everything at or below the configured level will be traced.
            // Technically 9 means trace everything, but the field is a UCHAR 
            // so 0xFF means definitely trace everything.
            ole32WppProvider.Level = 0xFF;  // 'TRACE_LEVEL_ALL'

            // Flags is a user-defined bitmask field the developer can use to group
            // related messages. 
            // Again, it is a UCHAR for WPP providers so 0xFF means trace everything.
            ole32WppProvider.Any = 0xFF;  // 'TRACE_FLAGS_ALL'

            // We need to enable this provider in order for krabs to correctly enable the OLE32 WPP events.
            trace.Enable(ole32WppProvider);

            // But we can't add any callbacks directly to krabs WPP providers though. Without the TMF
            // information, krabs cannot determine which provider the event belongs to.
            //
            // WPP providers, like MOF providers, return the message GUID in the ProviderId field.
            // So firstly krabs checks if the message GUID matches a provider GUID.
            // If you know the message GUIDs then you can create individual dummy providers for those.
            //
            // Secondly krabs queries TDH to see if it knows the provider GUID for the message GUID.
            // https://docs.microsoft.com/en-us/windows/win32/etw/retrieving-event-data-using-tdh
            // This works for registered MOF providers - but not for WPP providers. In this case, TDH returns
            // an all zero GUID - so we can create a dummy provider for that and add our callbacks there instead.
            // If you subscribe to multiple WPP providers, the events from *all* of them will be delivered to this dummy provider.
            var allWppDummyProvider = new Provider(Guid.Empty);
            allWppDummyProvider.OnEvent += (record) =>
            {
                // Here be dragons.
                //
                // krabs does not currently support TMF files for parsing WPP messages.
                // Instead you need to manually parse the UserData.
                //
                // The WPP macros generate message GUID globals named "WPP_<guid>_Traceguids"
                // They also generate logging staging functions named "WPP_SF_<format specifiers>"
                //
                // There seems to be a one-to-one mapping between message GUIDs and staging functions.
                // WPP events are a slightly different format to the modern ETW events. In particular,
                // they include this message GUID rather than the provider's control GUID.
                //
                // So message GUIDs would be a good candidate for filtering...
                // ... but my experience is that they may change between builds.
                // So I've subscribed to the zero GUID instead.
                //
                // Event ids seem more stable, but they are only unique per message GUID.
                //
                // In this case, combase.dll only has two logging staging functions.
                // WPP_SF_S(...) - which tells us that the event contains a single unicode string.
                // WPP_SF_ssdDsS(...) - which tells us that there are 3 ansi strings, a unicode string and dword.
                //
                // So we can brute force the format...

                var message = $"Message:{record.ProviderId} Id:{record.Id} ";
                var userData = record.UserData;
                var string_1 = Marshal.PtrToStringAnsi(record.UserData);
                if (string_1.Length != 1)  // definitely an ansi string...
                {
                    // WPP_SF_ssdDsS(...)
                    userData += string_1.Length + 1;
                    var string_2 = Marshal.PtrToStringAnsi(userData);
                    userData += string_2.Length + 1;
                    var int32_3 = Marshal.ReadInt32(userData);
                    userData += sizeof(Int32);
                    var uint32_4 = (UInt32)Marshal.ReadInt32(userData);
                    userData += sizeof(UInt32);
                    var string_5 = Marshal.PtrToStringAnsi(userData);
                    userData += string_5.Length + 1;
                    var string_6 = Marshal.PtrToStringUni(userData);
                    message += $"WPP_SF_ssdDsS({string_1}, {string_2}, {int32_3}, {uint32_4}, {string_5}, {string_6})";
                }
                else // probably a unicode string... (but possibly a single character ansi string)
                {
                    // WPP_SF_S(...)
                    string_1 = Marshal.PtrToStringUni(record.UserData);
                    message += $"WPP_SF_S({string_1})";
                }

                // In this example we only print messages that contain COM class ids.
                if (message.Contains(" clsid"))
                    Console.WriteLine(message);
            };
            trace.Enable(allWppDummyProvider);

            // Side note - if you want to turn up the verbosity of your COM WPP diagnostic tracing, then enable
            // OLE32 tracing via the registry following the instruction here -
            // https://support.microsoft.com/en-us/help/926098/how-to-enable-com-and-com-diagnostic-tracing
            //
            // Alternatively call _ControlTracing (4) via combase's 18f70770-8e64-11cf-9af1-0020af6e72f4 RPC interface.

            trace.Start();
        }
    }
}