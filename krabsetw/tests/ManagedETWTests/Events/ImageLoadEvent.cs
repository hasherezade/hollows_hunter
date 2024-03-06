// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.O365.Security.ETW.Kernel;
using Microsoft.O365.Security.ETW.Testing;

namespace EtwTestsCS.Events
{
    // For reference later:
    // https://msdn.microsoft.com/en-us/library/windows/desktop/aa364083(v=vs.85).aspx

    public class ImageLoadEvent
    {
        public readonly static string ProcessId = "ProcessId";
        public readonly static string FileName = "FileName";

        public readonly static Guid ProviderId = new ImageLoadProvider().Id;
        public readonly static int EventId = 0;
        public readonly static int Version = 3;
        public readonly static int OpCode = 2;

        public static SynthRecord CreateRecord(
            uint processId,
            string fileName)
        {
            using (var rb = new RecordBuilder(ProviderId, EventId, Version, OpCode))
            {
                // NOTE: kernel events MUST have this flag set
                rb.Header.Flags = (ushort)EventHeaderFlags.TRACE_MESSAGE;

                rb.AddValue(ProcessId, processId);
                rb.AddUnicodeString(FileName, fileName);

                return rb.PackIncomplete();
            }
        }
    }
}
