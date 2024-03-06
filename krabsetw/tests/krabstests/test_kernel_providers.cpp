// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "CppUnitTest.h"
#include <krabs.hpp>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace krabstests
{
    TEST_CLASS(test_kernel_providers)
    {
    public:

        TEST_METHOD(should_be_instantiatable_compilation_test)
        {
            krabs::kernel_provider provider(EVENT_TRACE_FLAG_ALPC, krabs::guids::alpc);
            krabs::kernel::thread_dispatch_provider cs;
            krabs::kernel_provider ob_trace(krabs::guids::ob_trace, PERF_OB_HANDLE | PERF_OB_OBJECT);
            krabs::kernel_provider alpc_provider(krabs::guids::alpc, PERF_ALPC);
        }

        TEST_METHOD(should_allow_event_registration)
        {
            krabs::kernel::thread_dispatch_provider cs;
            cs.add_on_event_callback([](const EVENT_RECORD &, const krabs::trace_context &) {});
        }

        TEST_METHOD(should_be_addable_to_a_kernel_trace)
        {
            krabs::kernel_trace trace;
            krabs::kernel::thread_dispatch_provider cs;
            trace.enable(cs);
        }

        TEST_METHOD(should_filter_kernel_events_by_guid)
        {
            bool calledAlpc = false;
            bool calledImageLoad = false;

            krabs::kernel_trace trace;
            krabs::kernel::image_load_provider cs;
            cs.add_on_event_callback([&](const EVENT_RECORD &, const krabs::trace_context &) {
                calledImageLoad = true;
            });
            trace.enable(cs);

            krabs::kernel::alpc_provider ap;
            ap.add_on_event_callback([&](const EVENT_RECORD &, const krabs::trace_context &) {
                calledAlpc = true;
            });
            trace.enable(ap);

            krabs::testing::record_builder builder(
                krabs::guids::image_load,
                krabs::id(0),
                krabs::version(3),
                krabs::opcode(10));

            builder.header().Flags = EVENT_HEADER_FLAG_CLASSIC_HEADER
                | EVENT_HEADER_FLAG_64_BIT_HEADER
                | EVENT_HEADER_FLAG_PROCESSOR_INDEX;

            auto record = builder.pack_incomplete();
            krabs::testing::kernel_trace_proxy proxy(trace);
            proxy.push_event(record);

            Assert::IsTrue(calledImageLoad);
            Assert::IsFalse(calledAlpc);
        }
    };
}