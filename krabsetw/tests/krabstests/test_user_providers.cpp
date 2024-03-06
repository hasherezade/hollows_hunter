// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "CppUnitTest.h"
#include <krabs.hpp>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace krabstests
{
    constexpr auto TEST_TRACE_NAME = L"krabs test named trace";

    static DWORD WINAPI threadproc(void*)
    {
        krabs::provider<> foo(L"Microsoft-Windows-WinINet");
        return 0;
    }

    static DWORD WINAPI starttrace_threadproc(void*)
    {
        krabs::user_trace trace(TEST_TRACE_NAME);
        krabs::provider<> foo(L"Microsoft-Windows-WinINet");
        trace.enable(foo);
        trace.start();
        return 0;
    }

    TEST_CLASS(test_user_providers)
    {
    public:

        TEST_METHOD(should_be_instantiatable_compilation_test)
        {
            krabs::provider<> foo(krabs::guid::random_guid());
        }

        TEST_METHOD(should_be_instantiatable_by_name)
        {
            // Because of VS's goobiness, we need a new thread
            // to create this type in. VS Test Runner starts the current
            // thread and initializes the STA COM apartment but krabsetw
            // wants to initialize as a MTA COM apartment.
            DWORD thread_id = 0;

             HANDLE my_thread = CreateThread(
                nullptr,
                0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(threadproc),
                nullptr,
                0,
                &thread_id);

            Assert::IsFalse(my_thread == nullptr);

            // Infinite wait... which should actually be fine
            // since we are literally creating a type and returning.
            WaitForSingleObject(my_thread, INFINITE);

            if (my_thread != nullptr) CloseHandle(my_thread);
        }

        TEST_METHOD(should_allow_event_registration)
        {
            krabs::provider<> foo(krabs::guid::random_guid());
            foo.add_on_event_callback([](const EVENT_RECORD &, const krabs::trace_context &) {});
        }

        TEST_METHOD(should_allow_any_all_level_flag_settings)
        {
            krabs::provider<> foo(krabs::guid::random_guid());
            foo.any(0x23);
            foo.all(0xFF);
            foo.level(0x0);
        }

        TEST_METHOD(should_be_addable_to_user_trace)
        {
            krabs::user_trace trace;
            krabs::provider<> foo(krabs::guid::random_guid());
            trace.enable(foo);
        }

        TEST_METHOD(should_allow_user_trace_stop_by_name_without_start)
        {
            // start a trace in another thread and orphan it
            DWORD thread_id = 0;
            HANDLE my_thread = CreateThread(
                nullptr,
                0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(starttrace_threadproc),
                nullptr,
                0,
                &thread_id);
            Assert::IsFalse(my_thread == nullptr);

            // create a new user_trace with the same name
            // we never call open/start for this user_trace ourselves, but
            // we can still query it to determine if a trace with a
            // matching name is running
            krabs::user_trace trace(TEST_TRACE_NAME);
            while (0 == trace.query_stats().buffersCount) {
                Sleep(500);
            }

            // and we can stop traces by name
            trace.stop();

            // wait for the orphaned trace to stop, and its thread to return
            WaitForSingleObject(my_thread, INFINITE);
            CloseHandle(my_thread);

            // no buffers --> trace has stopped
            Assert::IsTrue(0 == trace.query_stats().buffersCount);
        }

        TEST_METHOD(should_get_same_trace_flags_as_set)
        {
            // Take up the full width of the datatype.
            const ULONG FLAGS = 0xFFFFFFFF;

            krabs::provider<> foo(krabs::guid::random_guid());
            foo.trace_flags(FLAGS);
            Assert::IsTrue(foo.trace_flags() == FLAGS);
        }
    };
}