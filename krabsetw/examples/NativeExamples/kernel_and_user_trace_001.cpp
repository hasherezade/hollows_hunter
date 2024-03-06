// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example shows how to use a user_trace and a kernel_trace in the same program.

#include <iostream>
#include <thread>
#include <condition_variable>
#include "..\..\krabs\krabs.hpp"
#include "examples.h"

static void setup_ps_provider(krabs::provider<>& provider);
static void setup_image_load_provider(krabs::kernel::image_load_provider& provider);

void kernel_and_user_trace_001::start()
{
    // user_trace instances should be used for any non-kernel traces that are defined
    // by components or programs in Windows. You can have multiple ETW traces in a given
    // program but each trace object will consume one thread.
    krabs::user_trace user;
    krabs::kernel_trace kernel;

    // A trace can have any number of providers, which are identified by GUID or
    // a specific trace name.
    //
    // The GUIDs are defined by the components that emit events, and their GUIDs can
    // usually be found with various ETW tools (like wevutil or Microsoft Message Analyzer).
    krabs::provider<> ps_provider(krabs::guid(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}"));
    krabs::kernel::image_load_provider image_load_provider;

    setup_ps_provider(ps_provider);
    setup_image_load_provider(image_load_provider);

    // The user_trace needs to know about the provider that we've set up.
    // You can assign multiple providers to a single trace.
    user.enable(ps_provider);
    kernel.enable(image_load_provider);

    // Begin listening for events. This call blocks, so if you want to do other things
    // while this runs, you'll need to call this on another thread.
    //
    // Additionally, if multiple threads are enabling providers with a single trace object,
    // you'll need to synchronize the call to start. Because 'start' is a blocking call,
    // it will prevent any other thread from enabling additional providers.
    std::thread user_thread([&user]() { user.start(); });
    std::thread kernel_thread([&kernel]() { kernel.start(); });

    // Let the traces process for 30 seconds.
    std::cout << "starting traces..." << std::endl;
    Sleep(10000);
    std::cout << "stopping traces..." << std::endl;
    user.stop();
    kernel.stop();

    user_thread.join();
    kernel_thread.join();
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

void setup_image_load_provider(krabs::kernel::image_load_provider& provider)
{
    // Kernel providers accept all the typical callback mechanisms.
    provider.add_on_event_callback([](const EVENT_RECORD &record, const krabs::trace_context &trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);

        // Opcodes can be found on the kernel provider's documentation:
        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa364068(v=vs.85).aspx
        if (schema.event_opcode() == 10) {
            krabs::parser parser(schema);
            std::wstring filename = parser.parse<std::wstring>(L"FileName");
            std::wcout << L"Loaded image from file " << filename << std::endl;
        }
    });
}