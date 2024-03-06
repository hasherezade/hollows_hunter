// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example shows the event faking functionality lobster offers. This is useful
// for generating fake events that can be used to test client code.

using System;
using Microsoft.O365.Security.ETW;
using Testing = Microsoft.O365.Security.ETW.Testing;

namespace ManagedExamples
{
    public static class FakingEvents001
    {
        public static void Start()
        {
            // The usual suspects for setting up the trace...
            var trace = new Microsoft.O365.Security.ETW.UserTrace("My Named Trace");

            var powershellGuid = Guid.Parse("{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            var powershellProvider = new Microsoft.O365.Security.ETW.Provider(powershellGuid);
            powershellProvider.Any = Provider.AllBitsSet;

            powershellProvider.OnEvent += (record) =>
            {
                Console.WriteLine("Event properties:");
                foreach (Property prop in record.Properties)
                {
                    Console.WriteLine("\t" + prop.Name);
                }
            };

            trace.Enable(powershellProvider);

            // Normally, we'd call trace.Start() to begin listening, but we
            // want to test our code without actually starting a trace and
            // listening for an event. We kick up a proxy for the user trace
            // to offer us this functionality.
            var proxy = new Testing.Proxy(trace);

            // In order to push an event through the trace, we need to
            // manufacture an event. We can use a RecordBuilder to do this.
            var builder = new Testing.RecordBuilder(powershellGuid, 7937, 1);

            // For some events, there may be flags that need to be set to
            // arcane values. Forcing event schema lookup like this without a
            // real event is a little shady anyway, so this is only marginally
            // supported by doing something like the following:
            // builder.Header.Flags = 102938123908 // some magic number
            //
            // The magic numbers are often derived by looking at a real event
            // in a debugger and setting the Flags to the appropriate values.
            // There's nothing that we can really do to make this easier, so
            // sorry. :(

            // We can add some properties to the builder.
            builder.AddUnicodeString("ContextInfo", "Some silly test value here");
            builder.AddUnicodeString("Data", "Some other data here");

            // We need to pack the property into a record. There are two
            // functions that allow this -- Pack and PackIncomplete. Pack
            // validates that we've filled all the properties in the schema for
            // the event we're composing. PackIncomplete allows us to only fill
            // some events and fills with default values the ones we didn't
            // bother with.
            var packed = builder.PackIncomplete();

            // Now that we've got an event, we can push it through the proxy.
            proxy.PushEvent(packed);
        }
    }
}
