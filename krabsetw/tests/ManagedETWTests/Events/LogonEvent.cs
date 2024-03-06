// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.O365.Security.ETW.Testing;

namespace EtwTestsCS.Events
{
    public static class LogonEvent
    {
        public readonly static string TargetUserName = "TargetUserName";
        public readonly static string LogonType = "LogonType";

        public readonly static Guid ProviderId = Guid.Parse("199FE037-2B82-40A9-82AC-E1D46C792B99");
        public readonly static int EventId = 301;
        public readonly static int Version = 0;

        public static SynthRecord CreateRecord(
            string username,
            uint logonType)
        {
            using (var rb = new RecordBuilder(ProviderId, EventId, Version))
            {
                rb.AddUnicodeString(TargetUserName, username);
                rb.AddValue(LogonType, logonType);

                return rb.PackIncomplete();
            }
        }
    }
}
