// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.O365.Security.ETW.Testing;

namespace EtwTestsCS.Events
{
    public static class PowerShellEvent
    {
        public readonly static string UserData = "UserData";
        public readonly static string ContextInfo = "ContextInfo";
        public readonly static string Payload = "Payload";

        public readonly static Guid ProviderId = Guid.Parse("a0c1853b-5c40-4b15-8766-3cf1c58f985a");
        public readonly static int EventId = 7937;
        public readonly static int Version = 1;

        public static SynthRecord CreateRecord(
            string userData,
            string contextInfo,
            string payload)
        {
            using (var rb = new RecordBuilder(ProviderId, EventId, Version))
            {
                rb.AddUnicodeString(UserData, userData);
                rb.AddUnicodeString(ContextInfo, contextInfo);
                rb.AddUnicodeString(Payload, payload);

                return rb.Pack();
            }
        }

        public static SynthRecord CreateRecordWithContainerId(
            string userData,
            string contextInfo,
            string payload,
            Guid containerId)
        {
            using (var rb = new RecordBuilder(ProviderId, EventId, Version))
            {
                rb.AddUnicodeString(UserData, userData);
                rb.AddUnicodeString(ContextInfo, contextInfo);
                rb.AddUnicodeString(Payload, payload);

                rb.AddContainerId(containerId);

                return rb.Pack();
            }
        }
    }
}
