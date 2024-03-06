// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example shows the event faking functionality krabs offers. This is useful
// for generating fake events that can be used to test client code.

#include <iostream>
#include <cassert>

#include "..\..\krabs\krabs.hpp"
#include "examples.h"

void testing_001::start()
{
    krabs::user_trace trace(L"My Named Trace");

    krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
    krabs::provider<> powershellProvider(powershell);
    powershellProvider.any(0xf0010000000003ff);

    powershellProvider.add_on_event_callback([](const EVENT_RECORD &record, const krabs::trace_context &trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        krabs::parser parser(schema);
        std::wstring context = parser.parse<std::wstring>(L"ContextInfo");
        std::wcout << L"Event called with context " << context << std::endl;
    });

    trace.enable(powershellProvider);

    // Normally, one would call trace.start() to begin listening, but we want
    // to test our code without actually starting a trace and listening for an
    // event. We kick up a proxy for the user trace to offer us this functionality.
    krabs::testing::user_trace_proxy proxy(trace);

    // In order to push an event through the trace, we need to manufacture an
    // event. We can use record_builder to do this.
    krabs::testing::record_builder builder(powershell, krabs::id(7937), krabs::version(1));

    // For some events, there may be flags that need to be set to some arcane values. Forcing
    // event schema lookup like this without a real event is a little shady anyway, so this
    // is only marginally supported by doing something like the following:
    // builder.header().Flags = EVENT_HEADER_FLAG_CLASSIC_HEADER
    //                        | EVENT_HEADER_FLAG_64_BIT_HEADER
    //                        | EVENT_HEADER_FLAG_PROCESSOR_INDEX;
    //
    // These values are often derived by looking at a real event in a debugger and setting
    // the Flags to the appropriate values.


    // We can add our own property values to the builder.
    builder.add_properties()
        (L"ContextInfo", L"Some silly test values here")
        (L"Data", L"Some other data here");

    // We need to pack the property into an EVENT_RECORD structure. There are two functions
    // that allow for this -- pack and pack_incomplete. pack validates that we've filled all
    // the properties in the schema for the event we're composing. pack_incomplete allows for
    // us to only fill some events and default-fills the ones we didn't bother with.
    auto record = builder.pack_incomplete();

    // Now that we've got an event, we can push it through the trace.
    proxy.push_event(record);
}
