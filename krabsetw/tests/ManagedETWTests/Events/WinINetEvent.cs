// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.O365.Security.ETW.Testing;

namespace EtwTestsCS.Events
{
    public static class WinINetEvent
    {
        public readonly static string URL = "URL";
        public readonly static string Verb = "Verb";
        public readonly static string Status = "Status";

        public readonly static Guid ProviderId = Guid.Parse("43D1A55C-76D6-4F7E-995C-64C711E5CAFE");
        public readonly static int EventId = 1057;
        public readonly static int Version = 0;

        public static SynthRecord CreateRecord(
            string url,
            string verb,
            uint status)
        {
            using (var rb = new RecordBuilder(ProviderId, EventId, Version))
            {
                rb.AddAnsiString(URL, url);
                rb.AddAnsiString(Verb, verb);
                rb.AddValue(Status, status);

                return rb.PackIncomplete();
            }
        }
    }
}
