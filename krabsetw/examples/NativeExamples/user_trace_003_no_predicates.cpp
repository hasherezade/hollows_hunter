// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// Krabs supports provider filtering based on ETW API filtering features.
// This example listening for file delete event.
//

#include <iostream>
#include <cassert>

#include "..\..\krabs\krabs.hpp"
#include "examples.h"

void user_trace_003_no_predicates::start()
{
    // user_trace instances should be used for any non-kernel traces that are defined
    // by components or programs in Windows. They can optionally take a name -- if none
    // is provided, a random GUID is assigned as the name.
    krabs::user_trace trace(L"My Named Trace");

    // A trace can have any number of providers, which are identified by GUID. These
    // GUIDs are defined by the components that emit events, and their GUIDs can
    // usually be found with various ETW tools (like wevutil).

    //listen for file events
    krabs::provider<> provider(krabs::guid(L"{EDD08927-9CC4-4E65-B970-C2560FB5C289}"));

    // In user_trace_001.cpp we manually filter events by checking the event information
    // In user_trace_002.cpp we filter events using provider predicates
    // In user_trace_003.cpp we filter with ETW filtering only without predicate
    // In this example, we're going to use a provider filter based on ETW filtering features
    // combined with predicate which does additional filtering

    // We instantiate an event_filter first. An event_filter is created with a
    // event id which will be forwarded as filter to etw tracing api
    krabs::event_filter filter(11);

    auto cb = [](const EVENT_RECORD &record, const krabs::trace_context &trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        assert(schema.event_id() == 11);
        std::wcout << L"Event " + std::to_wstring(schema.event_id()) +  L" received!" << std::endl;
    };

    filter.add_on_event_callback(cb);

    // event_filters are attached to providers. Events that are attached to a filter will
    // only be called when the filter allows the event through. Any events attached to the
    // provider directly will be called for all events that are fired by the ETW producer.
    provider.add_filter(filter);
    trace.enable(provider);
    trace.start();
}
