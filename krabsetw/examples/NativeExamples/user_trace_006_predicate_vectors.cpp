// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example shows how to use the any_of/all_of/none_of filter predicate vectors.

#include <iostream>
#include <cassert>

#include "..\..\krabs\krabs.hpp"
#include "examples.h"

void user_trace_006_predicate_vectors::start()
{
    krabs::user_trace trace(L"My Named Trace");

    // We will use the Process Trace
    krabs::provider<> provider(L"Microsoft-Windows-Kernel-Process");
    provider.any(0x10);

    // We'll log events where one of the following is true
    //  - The Opcode is 1,
    //  - The Event ID is 2, or
    //  - The Version is 3
    krabs::predicates::opcode_is opcode_is_1 = krabs::predicates::opcode_is(1);
    krabs::predicates::id_is eventid_is_2 = krabs::predicates::id_is(2);
    krabs::predicates::version_is version_is_3 = krabs::predicates::version_is(3);

    krabs::event_filter filter(
        krabs::predicates::any_of({
            &opcode_is_1,
            &eventid_is_2,
            &version_is_3,
        })
    );
    filter.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        assert(schema.event_id() == 1 || schema.event_id() == 2);
        printf("Event ID: %d || Opcode: %d || Version %d\n", schema.event_id(), schema.event_opcode(), schema.event_version());
        });

    provider.add_filter(filter);
    trace.enable(provider);
    trace.start();
}
