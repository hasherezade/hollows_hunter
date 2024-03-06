// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example shows how to use a user_trace to extract powershell command
// invocations. It demonstrates provider-level filtering to make event handling
// code a little simpler.

#include <iostream>
#include <cassert>

#include "..\..\krabs\krabs.hpp"
#include "examples.h"

void user_trace_002::start()
{
    // user_trace instances should be used for any non-kernel traces that are defined
    // by components or programs in Windows. They can optionally take a name -- if none
    // is provided, a random GUID is assigned as the name.
    krabs::user_trace trace(L"My Named Trace");

    // A trace can have any number of providers, which are identified by GUID. These
    // GUIDs are defined by the components that emit events, and their GUIDs can
    // usually be found with various ETW tools (like wevutil).
    krabs::provider<> provider(krabs::guid(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}"));
    provider.any(0xf0010000000003ff);

    // In user_trace_001.cpp, we manually filter events by checking the event information
    // in our callback functions. In this example, we're going to use a provider filter
    // to do this for us.

    // We instantiate an event_filter first. An event_filter is created with a
    // predicate -- literally just a function that does some check on an EVENT_RECORD
    // and returns a boolean -- true when the event should be passed on to callbacks,
    // and false otherwise.

    // krabs provides a few simple predicates to use to make this a little easier for
    // the standard cases. We'll use one of those to filter based on the event id.
    krabs::event_filter filter(krabs::predicates::id_is(7937));

    // event_filters can have attached callbacks, just like a regular provider.
    filter.add_on_event_callback([](const EVENT_RECORD &record, const krabs::trace_context &trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        assert(schema.event_id() == 7937);
        std::wcout << L"Event 7937 received!" << std::endl;
    });

    // event_filters are attached to providers. Events that are attached to a filter will
    // only be called when the filter allows the event through. Any events attached to the
    // provider directly will be called for all events that are fired by the ETW producer.
    provider.add_filter(filter);
    trace.enable(provider);
    trace.start();
}
