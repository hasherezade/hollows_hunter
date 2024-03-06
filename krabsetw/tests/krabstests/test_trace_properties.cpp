// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "CppUnitTest.h"
#include <krabs.hpp>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace krabstests
{
    TEST_CLASS(test_trace_properties)
    {
    public:

        TEST_METHOD(should_set_properties)
        {
            SYSTEM_INFO sysinfo;
            GetSystemInfo(&sysinfo);
            auto numberOfProcessors = sysinfo.dwNumberOfProcessors;

            EVENT_TRACE_PROPERTIES properties = { 0 };
            properties.BufferSize = 1024;
            properties.MinimumBuffers = numberOfProcessors * 2 + 1;
            properties.MaximumBuffers = properties.MinimumBuffers + 1;
            properties.FlushTimer = 2;
            properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;

            constexpr auto TEST_TRACE_NAME = L"krabs properties test";
            krabs::user_trace trace(TEST_TRACE_NAME);
            trace.set_trace_properties(&properties);
            (void)trace.open();

            krabs::details::trace_info info = {};
            info.properties.Wnode.BufferSize = sizeof(krabs::details::trace_info);
            info.properties.LoggerNameOffset = offsetof(krabs::details::trace_info, logfileName);
            ULONG status = ControlTraceW(NULL, TEST_TRACE_NAME, &info.properties, EVENT_TRACE_CONTROL_QUERY);
            Assert::IsTrue(status == ERROR_SUCCESS);

            Assert::IsTrue(properties.BufferSize == info.properties.BufferSize);
            Assert::IsTrue(properties.MinimumBuffers == info.properties.MinimumBuffers);
            Assert::IsTrue(properties.MaximumBuffers == info.properties.MaximumBuffers);
            Assert::IsTrue(properties.FlushTimer == info.properties.FlushTimer);
            Assert::IsTrue(EVENT_TRACE_REAL_TIME_MODE == (info.properties.LogFileMode & EVENT_TRACE_REAL_TIME_MODE));
            Assert::IsTrue(EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING != (info.properties.LogFileMode & EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING));
        }

        TEST_METHOD(sane_default_properties)
        {
            constexpr auto TEST_TRACE_NAME = L"krabs properties test";
            krabs::user_trace trace(TEST_TRACE_NAME);
            (void)trace.open();

            krabs::details::trace_info info = {};
            info.properties.Wnode.BufferSize = sizeof(krabs::details::trace_info);
            info.properties.LoggerNameOffset = offsetof(krabs::details::trace_info, logfileName);
            ULONG status = ControlTraceW(NULL, TEST_TRACE_NAME, &info.properties, EVENT_TRACE_CONTROL_QUERY);
            Assert::IsTrue(status == ERROR_SUCCESS);

            Assert::IsTrue(info.properties.BufferSize > 0);
            Assert::IsTrue(info.properties.BufferSize <= 1024);  // maximum allowed = 1024KB
            Assert::IsTrue(info.properties.MinimumBuffers = 2); // EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING -> assumes single processer
            Assert::IsTrue(info.properties.MaximumBuffers > 2);
            Assert::IsTrue(info.properties.FlushTimer == 1); // flush every second -> despite MS documentation that zero is 'flush when full'
            Assert::IsTrue(EVENT_TRACE_REAL_TIME_MODE == (info.properties.LogFileMode & EVENT_TRACE_REAL_TIME_MODE));
            Assert::IsTrue(EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING == (info.properties.LogFileMode & EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING));
        }
    };
}