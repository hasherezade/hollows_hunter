// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example shows how to use a user_trace with multiple providers.

#include <iostream>
#include "..\..\krabs\krabs.hpp"
#include "examples.h"

static void setup_ps_provider(krabs::provider<>& provider);
static void setup_wininet_provider(krabs::provider<>& provider);

void multiple_providers_001::start()
{
    // user_trace instances should be used for any non-kernel traces that are defined
    // by components or programs in Windows.
    krabs::user_trace trace;

    // A trace can have any number of providers, which are identified by GUID or
    // a specific trace name.
    //
    // The GUIDs are defined by the components that emit events, and their GUIDs can
    // usually be found with various ETW tools (like wevutil or Microsoft Message Analyzer).
    krabs::provider<> ps_provider(krabs::guid(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}"));
    krabs::provider<> wininet_provider(L"Microsoft-Windows-WinINet");

    setup_ps_provider(ps_provider);
    setup_wininet_provider(wininet_provider);

    // The user_trace needs to know about the provider that we've set up.
    // You can assign multiple providers to a single trace.
    trace.enable(ps_provider);
    trace.enable(wininet_provider);

    // Begin listening for events. This call blocks, so if you want to do other things
    // while this runs, you'll need to call this on another thread.
    //
    // Additionally, if multiple threads are enabling providers with a single trace object,
    // you'll need to synchronize the call to start. Because 'start' is a blocking call,
    // it will prevent any other thread from enabling additional providers.
    trace.start();
}

void setup_ps_provider(krabs::provider<>& provider)
{
    // user_trace providers typically have any and all flags, whose meanings are
    // unique to the specific providers that are being invoked. To understand these
    // flags, you'll need to look to the ETW event producer.
    provider.any(0xf0010000000003ff);

    // providers should be wired up with functions (or functors) that are called when
    // events from that provider are fired.
    provider.add_on_event_callback([](const EVENT_RECORD &record, const krabs::trace_context &trace_context) {

        // Once an event is received, if we want krabs to help us analyze it, we need
        // to snap in a schema to ask it for information.
        krabs::schema schema(record, trace_context.schema_locator);

        // We then have the ability to ask a few questions of the event.
        std::wcout << L"Event " << schema.event_id();
        std::wcout << L"(" << schema.event_name() << L") received." << std::endl;

        if (schema.event_id() == 7937) {
            // The event we're interested in has a field that contains a bunch of
            // info about what it's doing. We can snap in a parser to help us get
            // the property information out.
            krabs::parser parser(schema);

            // We have to explicitly name the type that we're parsing in a template
            // argument.
            // We could alternatively use try_parse if we didn't want an exception to
            // be thrown in the case of failure.
            std::wstring context = parser.parse<std::wstring>(L"ContextInfo");
            std::wcout << L"\tContext: " << context << std::endl;
        }
    });
}

void setup_wininet_provider(krabs::provider<>& provider)
{
    // user_trace providers typically have any and all flags, whose meanings are
    // unique to the specific providers that are being invoked. To understand these
    // flags, you'll need to look to the ETW event producer.
    provider.all(0x4000000000000000);

    // providers should be wired up with functions (or functors) that are called when
    // events from that provider are fired.
    provider.add_on_event_callback([](const EVENT_RECORD &record, const krabs::trace_context &trace_context) {

        // Once an event is received, if we want krabs to help us analyze it, we need
        // to snap in a schema to ask it for information.
        krabs::schema schema(record, trace_context.schema_locator);

        // We then have the ability to ask a few questions of the event.
        std::wcout << L"Event " << schema.event_id();
        std::wcout << L"(" << schema.event_name() << L") received." << std::endl;

        // We'll filter on only cached and new WinINet requests/responses.
        if (schema.event_id() == 1057) {

            // The event we're interested in has a field that contains a bunch of
            // info about what it's doing. We can snap in a parser to help us get
            // the property information out.
            krabs::parser parser(schema);

            // We have to explicitly name the type that we're parsing in a template
            // argument.
            // We could alternatively use try_parse if we didn't want an exception to
            // be thrown in the case of failure.
            auto url = parser.parse<std::string>(L"URL");
            auto request_headers = parser.parse<std::string>(L"RequestHeaders");
            auto response_headers = parser.parse<std::string>(L"ResponseHeaders");
            std::cout << "\tURL: " << url << std::endl;
            std::cout << "\t\tRequest Headers: " << request_headers << std::endl;
            std::cout << "\t\tResponse Headers: " << response_headers << std::endl;
        }
    });
}