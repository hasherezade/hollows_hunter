// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example shows how to use a user_trace to extract powershell command
// invocations. It uses event ID filtering built in to ETW for improved performance.

using System;
using Microsoft.O365.Security.ETW;

namespace ManagedExamples
{
    public static class UserTrace003
    {
        public static void Start()
        {
            // UserTrace instances should be used for any non-kernel traces that are defined
            // by components or programs in Windows. They can optionally take a name -- if none
            // is provided, a random GUID is assigned as the name.
            var trace = new UserTrace();

            // A trace can have any number of providers, which are identified by GUID. These
            // GUIDs are defined by the components that emit events, and their GUIDs can
            // usually be found with various ETW tools (like wevutil).
            var powershellProvider = new Provider(Guid.Parse("{A0C1853B-5C40-4B15-8766-3CF1C58F985A}"));

            // UserTrace providers typically have any and all flags, whose meanings are
            // unique to the specific providers that are being invoked. To understand these
            // flags, you'll need to look to the ETW event producer.
            powershellProvider.Any = Provider.AllBitsSet;

            // In UserTrace002.cs, we use predicate-based filtering to only emit events
            // for a specific event id.
            //
            // Alternatively, we can use ETW-based filtering which is even more performant.
            var filter = new EventFilter(7937);

            // EventFilters have attached callbacks, just like a regular provider.
            filter.OnEvent += (record) =>
            {
                System.Diagnostics.Debug.Assert(record.Id == 7937);
                Console.WriteLine("Event 7937 received");
            };

            // EventFilters are attached to providers. Events that are attached to the filter
            // will only be called when the filter allows the event through. Any events attached
            // to the provider directly will be called for all events that are fired by the ETW
            // producer.
            powershellProvider.AddFilter(filter);
            trace.Enable(powershellProvider);
            trace.Start();
        }
    }
}
