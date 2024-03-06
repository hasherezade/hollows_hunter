// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example shows how to use a user_trace to extract powershell command
// invocations. It demonstrates provider-level filtering to make event handling
// code a little simpler.

using System;
using Microsoft.O365.Security.ETW;

namespace ManagedExamples
{
    public static class UserTrace002
    {
        public static void Start()
        {
            // UserTrace instances should be used for any non-kernel traces that are defined
            // by components or programs in Windows. They can optionally take a name -- if none
            // is provided, a random GUID is assigned as the name.
            var trace = new UserTrace("Silly Gooby");

            // A trace can have any number of providers, which are identified by GUID. These
            // GUIDs are defined by the components that emit events, and their GUIDs can
            // usually be found with various ETW tools (like wevutil).
            var powershellProvider = new Provider(Guid.Parse("{A0C1853B-5C40-4B15-8766-3CF1C58F985A}"));

            // UserTrace providers typically have any and all flags, whose meanings are
            // unique to the specific providers that are being invoked. To understand these
            // flags, you'll need to look to the ETW event producer.
            powershellProvider.Any = Provider.AllBitsSet;

            // In user_trace_001.cs, we manually filter events by checking the information
            // in our callback functions. In this example, we're going to use a provider
            // filter to do this for us.

            // We instantiate an EventFilter first. An EventFilter is created with a predicate --
            // literally just a function that does some check on an EventRecord and returns a boolean
            // (true when the even should be passed on to callbacks, false otherwise).

            // EventFilters are more than just convenient -- Lobster provides combinators for
            // expressing simple but powerful filters that actually execute in the underlying C++
            // krabs library. This means that events can be filtered before ever running in the
            // CLR (saving us a ton of cost in spinning up objects on event firing).

            // The combinators cannot express everything a filter must do, so for complicated
            // filters, it's recommended to write the filters in a managed C++/CLI project and
            // use those to keep the perf benefits. The filters that Lobster provides are on
            // the Filter object (and can be combined with &&, ||, !)
            var filter = new EventFilter(Filter.EventIdIs(7937));

            // EventFilters have attached callbacks, just like a regular provider.
            filter.OnEvent += (record) =>
            {
                System.Diagnostics.Debug.Assert(record.Id == 7937);
                Console.WriteLine("Event 7937 received");
            };

            filter.OnError += (error) =>
            {
                Console.WriteLine($"Filter error: {error.Record.Id} {error.Message}");
            };

            powershellProvider.OnError += (error) =>
            {
                Console.WriteLine($"Provider error: {error.Record.Id} {error.Message}");
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
