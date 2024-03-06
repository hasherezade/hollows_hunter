// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "CppUnitTest.h"
#include <krabs.hpp>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
namespace adpt = krabs::predicates::adapters;

namespace krabstests
{
    TEST_CLASS(test_event_filter)
    {
        static krabs::testing::synth_record init()
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7937), krabs::version(1));
            builder.add_properties()(L"UserData", L">this counted string is 31 characters long, but the null character comes a lot after");
            builder.add_properties()(L"ContextInfo", L"Foo bar baz bingo");
            return builder.pack_incomplete();
        }

        krabs::testing::synth_record record = init();

        krabs::trace_context trace_context;

    public:
        TEST_METHOD(should_forward_calls_to_all_its_callbacks_with_an_identity_filter)
        {
            krabs::event_filter filter(krabs::predicates::any_event);

            auto was_called1 = false;
            auto was_called2 = false;

            filter.add_on_event_callback([&](const EVENT_RECORD &, const krabs::trace_context &) { was_called1 = true; });
            filter.add_on_event_callback([&](const EVENT_RECORD &, const krabs::trace_context &) { was_called2 = true; });

            krabs::testing::event_filter_proxy proxy(filter);
            proxy.push_event(record);

            Assert::IsTrue(was_called1);
            Assert::IsTrue(was_called2);
        }

        TEST_METHOD(should_not_forward_calls_that_dont_match_predicate)
        {
            krabs::event_filter filter(krabs::predicates::no_event);

            auto was_called1 = false;
            auto was_called2 = false;

            filter.add_on_event_callback([&](const EVENT_RECORD &, const krabs::trace_context &) { was_called1 = true; });
            filter.add_on_event_callback([&](const EVENT_RECORD &, const krabs::trace_context &) { was_called2 = true; });

            krabs::testing::event_filter_proxy proxy(filter);
            proxy.push_event(record);

            Assert::IsFalse(was_called1);
            Assert::IsFalse(was_called2);
        }

        TEST_METHOD(should_resolve_multiple_constructors_without_conflicts)
        {
            krabs::event_filter provider_filter_single_event_id(1);
            krabs::event_filter provider_filter_array_of_single_event_id({ 1 });
            krabs::event_filter provider_filter_array_of_multiple_event_ids({ 1, 2 });
        }

        TEST_METHOD(id_is_should_match_events_that_have_matching_ids)
        {
            krabs::predicates::id_is filter(7937);
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(id_is_should_match_events_that_dont_have_matching_ids)
        {
            krabs::predicates::id_is filter(8000);
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(version_is_should_match_events_that_have_matching_versions)
        {
            krabs::predicates::version_is filter(krabs::version(1));
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(version_is_should_not_match_events_that_dont_have_matching_versions)
        {
            krabs::predicates::version_is filter(krabs::version(2));
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(opcode_is_should_match_events_that_have_matching_opcodes)
        {
            krabs::predicates::opcode_is filter(krabs::opcode(0));
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(opcode_is_should_not_match_events_that_dont_have_matching_opcodes)
        {
            krabs::predicates::opcode_is filter(krabs::opcode(77));
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(property_is_should_match_events_with_matching_property_values)
        {
            auto filter = krabs::predicates::property_is(L"ContextInfo", std::wstring(L"Foo bar baz bingo"));
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(property_is_should_not_match_events_that_dont_have_matching_property_values)
        {
            auto filter = krabs::predicates::property_is(L"ContextInfo", std::wstring(L"Foo2"));
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(property_is_should_not_match_events_if_property_isnt_in_schema)
        {
            auto filter = krabs::predicates::property_is(L"SpecialSillyname", std::wstring(L"Foo2"));
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(property_equals_should_match_properties_that_exactly_match_expected)
        {
            auto filter = krabs::predicates::property_equals(L"ContextInfo", std::wstring(L"Foo bar baz bingo"));
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(property_equals_should_not_match_properties_that_dont_exactly_match_expected)
        {
            auto filter = krabs::predicates::property_equals(L"ContextInfo", std::wstring(L"I don't match"));
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(property_equals_should_match_counted_string_properties_that_exactly_match_expected)
        {
            auto filter = krabs::predicates::property_equals<adpt::counted_string>(L"UserData", std::wstring(L"this counted string is 31 chara"));
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(property_equals_should_not_match_counted_string_properties_that_do_not_exactly_match_expected)
        {
            auto filter = krabs::predicates::property_equals<adpt::counted_string>(L"UserData", std::wstring(L"I don't match"));
            Assert::IsFalse(filter(record, trace_context));
        }

        /* the ">" unicode character at the start corresponds to 0x003E, or 62. Therefore this function should only compare
        * the first 31 characters of the string, which ends at "... is 31 chara", and therefore should not match "charac"
        */
        TEST_METHOD(property_equals_should_not_match_counted_string_props_that_include_past_endof_string)
        {
            auto filter = krabs::predicates::property_equals<adpt::counted_string>(L"UserData", std::wstring(L"this counted string is 31 charac"));
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(property_iequals_should_match_properties_that_case_insensitive_match_expected)
        {
            auto filter = krabs::predicates::property_iequals(L"ContextInfo", std::wstring(L"Foo BAR BAZ BINgo"));
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(property_iequals_should_not_match_properties_that_dont_case_insensitive_match_expected)
        {
            auto filter = krabs::predicates::property_iequals(L"ContextInfo", std::wstring(L"I don't match"));
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(property_iequals_should_match_counted_string_properties_that_case_insensitive_match_expected)
        {
            auto filter = krabs::predicates::property_iequals<adpt::counted_string>(L"UserData", std::wstring(L"this cOUNTED STRING IS 31 chara"));
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(property_iequals_should_not_match_counted_string_properties_that_case_insensitive_match_expected)
        {
            auto filter = krabs::predicates::property_iequals<adpt::counted_string>(L"UserData", std::wstring(L"I don't match"));
            Assert::IsFalse(filter(record, trace_context));
        }

        /* the ">" unicode character at the start corresponds to 0x003E, or 62. Therefore this function should only compare
        * the first 31 characters of the string, which ends at "... is 31 chara", and therefore should not match "charac"
        */
        TEST_METHOD(property_iequals_should_not_match_counted_string_properties_that_include_past_string_end)
        {
            auto filter = krabs::predicates::property_iequals<adpt::counted_string>(L"UserData", std::wstring(L"this counTED STRING IS 31 charac"));
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(property_contains_should_match_properties_that_case_insensitive_match_expected)
        {
            auto filter = krabs::predicates::property_contains(L"ContextInfo", std::wstring(L"bar"));
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(property_contains_should_not_match_properties_that_dont_case_insensitive_match_expected)
        {
            auto filter = krabs::predicates::property_contains(L"ContextInfo", std::wstring(L"smile"));
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(property_contains_should_match_counted_string_properties_that_case_insensitive_match_expected)
        {
            auto filter = krabs::predicates::property_contains<adpt::counted_string>(L"UserData", std::wstring(L"counted string"));
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(property_contains_should_not_match_counted_string_properties_that_case_insensitive_match_expected)
        {
            auto filter = krabs::predicates::property_contains<adpt::counted_string>(L"UserData", std::wstring(L"unrelated string"));
            Assert::IsFalse(filter(record, trace_context));
        }

        /* the ">" unicode character at the start corresponds to 0x003E, or 62. Therefore this function should only compare
        * the first 31 characters of the string, which ends at "... is 31 chara", and therefore should not match "charac"
        */
        TEST_METHOD(property_contains_should_not_match_counted_string_properties_that_include_past_string_end)
        {
            auto filter = krabs::predicates::property_contains<adpt::counted_string>(L"UserData", std::wstring(L"charac"));
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(property_contains_should_match_counted_string_properties_that_contain_string_values_at_end)
        {
            auto filter = krabs::predicates::property_contains<adpt::counted_string>(L"UserData", std::wstring(L"chara"));
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(property_icontains_should_match_properties_that_case_insensitive_match_expected)
        {
            auto filter = krabs::predicates::property_icontains(L"ContextInfo", std::wstring(L"BaR"));
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(property_icontains_should_not_match_properties_that_dont_case_insensitive_match_expected)
        {
            auto filter = krabs::predicates::property_icontains(L"ContextInfo", std::wstring(L"sMiLE"));
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(property_icontains_should_match_counted_string_properties_that_case_insensitive_match_expected)
        {
            auto filter = krabs::predicates::property_icontains<adpt::counted_string>(L"UserData", std::wstring(L"cOUnTeD stRIng"));
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(property_icontains_should_not_match_counted_string_properties_that_case_insensitive_match_expected)
        {
            auto filter = krabs::predicates::property_icontains<adpt::counted_string>(L"UserData", std::wstring(L"unRElATed sTRiNg"));
            Assert::IsFalse(filter(record, trace_context));
        }

        /* the ">" unicode character at the start corresponds to 0x003E, or 62. Therefore this function should only compare
        * the first 31 characters of the string, which ends at "... is 31 chara", and therefore should not match "charac"
        */
        TEST_METHOD(property_icontains_should_not_match_counted_string_properties_that_include_past_string_end)
        {
            auto filter = krabs::predicates::property_icontains<adpt::counted_string>(L"UserData", std::wstring(L"chaRaC"));
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(property_icontains_should_match_counted_string_properties_that_contain_string_values_at_end_of_len)
        {
            auto filter = krabs::predicates::property_icontains<adpt::counted_string>(L"UserData", std::wstring(L"cHaRa"));
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(property_starts_with_should_match_properties_that_starts_with_expected)
        {
            auto filter = krabs::predicates::property_starts_with(L"ContextInfo", std::wstring(L"Foo bar"));
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(property_starts_with_should_not_match_properties_that_doesnt_starts_with_expected)
        {
            auto filter = krabs::predicates::property_starts_with(L"ContextInfo", std::wstring(L"baz bingo"));
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(property_starts_with_should_match_counted_string_properties_that_starts_with_expected)
        {
            auto filter = krabs::predicates::property_starts_with<adpt::counted_string>(L"UserData", std::wstring(L"this counted"));
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(property_starts_with_should_not_match_counted_string_properties_that_starts_with_expected)
        {
            auto filter = krabs::predicates::property_starts_with<adpt::counted_string>(L"UserData", std::wstring(L"string is"));
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(property_starts_with_should_not_match_with_unicode_length_character_at_start)
        {
            auto filter = krabs::predicates::property_starts_with<adpt::counted_string>(L"UserData", std::wstring(L">"));
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(property_starts_with_should_not_match_events_that_go_past_given_counted_string_len)
        {
            auto filter = krabs::predicates::property_starts_with<adpt::counted_string>(L"UserData", std::wstring(L"this counted string is 31 charac"));
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(property_istarts_with_should_match_events_that_start_with_expected)
        {
            auto filter = krabs::predicates::property_istarts_with(L"ContextInfo", std::wstring(L"fOo BAr"));
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(property_istarts_with_should_not_match_events_that_do_not_match_expected)
        {
            auto filter = krabs::predicates::property_istarts_with(L"ContextInfo", std::wstring(L"baZ bINgo"));
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(property_istarts_with_should_match_counted_string_with_events_that_start_with_expected)
        {
            auto filter = krabs::predicates::property_istarts_with<adpt::counted_string>(L"UserData", std::wstring(L"tHIs CouNTed"));
            Assert::IsTrue(filter(record, trace_context));
        }

        /* the ">" unicode character at the start corresponds to 0x003E, or 62. Therefore this function should only compare
        * the first 31 characters of the string, which ends at "... is 31 chara", and therefore should not match "charac"
        */
        TEST_METHOD(property_istarts_with_should_not_match_counted_string_with_events_that_start_with_expected)
        {
            auto filter = krabs::predicates::property_istarts_with<adpt::counted_string>(L"UserData", std::wstring(L"stRING is"));
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(property_istarts_with_should_not_match_events_that_start_with_unicode_length_char)
        {
            auto filter = krabs::predicates::property_istarts_with<adpt::counted_string>(L"UserData", std::wstring(L">"));
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(property_istarts_with_should_not_match_events_that_go_past_given_counted_string_len)
        {
            auto filter = krabs::predicates::property_istarts_with<adpt::counted_string>(L"UserData", std::wstring(L"thIS coUNteD stRINg is 31 chArac"));
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(property_ends_with_should_match_properties_that_ends_with_expected)
        {
            auto filter = krabs::predicates::property_ends_with(L"ContextInfo", std::wstring(L"baz bingo"));
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(property_ends_with_should_not_match_properties_that_doesnt_ends_with_expected)
        {
            auto filter = krabs::predicates::property_ends_with(L"ContextInfo", std::wstring(L"Foo bar"));
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(property_ends_with_should_match_counted_string_properties_that_ends_with_expected)
        {
            auto filter = krabs::predicates::property_ends_with<adpt::counted_string>(L"UserData", std::wstring(L"is 31 chara"));
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(property_ends_with_should_not_match_counted_string_properties_that_ends_with_expected)
        {
            auto filter = krabs::predicates::property_ends_with<adpt::counted_string>(L"UserData", std::wstring(L"a lot after"));
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(property_ends_with_should_not_match_events_that_go_past_given_counted_string_len)
        {
            auto filter = krabs::predicates::property_ends_with<adpt::counted_string>(L"UserData", std::wstring(L"this counted string is 31 charac"));
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(property_iends_with_should_match_events_that_start_with_expected)
        {
            auto filter = krabs::predicates::property_iends_with(L"ContextInfo", std::wstring(L"baZ bINgo"));
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(property_iends_with_should_not_match_events_that_do_not_match_expected)
        {
            auto filter = krabs::predicates::property_iends_with(L"ContextInfo", std::wstring(L"fOo BAr"));
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(property_iends_with_should_match_counted_string_with_events_that_end_with_expected)
        {
            auto filter = krabs::predicates::property_iends_with<adpt::counted_string>(L"UserData", std::wstring(L"iS 31 chaRa"));
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(property_iends_with_should_not_match_counted_string_with_events_that_with_with_expected)
        {
            auto filter = krabs::predicates::property_iends_with<adpt::counted_string>(L"UserData", std::wstring(L"a LOT aFteR"));
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(property_iends_with_should_not_match_events_that_go_past_given_counted_string_len)
        {
            auto filter = krabs::predicates::property_iends_with<adpt::counted_string>(L"UserData", std::wstring(L"thIS coUNteD stRINg is 31 chArac"));
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(and_should_match_an_event_if_both_components_match)
        {
            auto filter = krabs::predicates::and_filter(krabs::predicates::any_event, krabs::predicates::any_event);
            Assert::IsTrue(filter(record, trace_context));

            auto filter2 = krabs::predicates::and_filter(krabs::predicates::id_is(7937), krabs::predicates::version_is(1));
            Assert::IsTrue(filter2(record, trace_context));
        }

        TEST_METHOD(and_should_not_match_if_left_component_does_not_match)
        {
            auto filter = krabs::predicates::and_filter(krabs::predicates::no_event, krabs::predicates::any_event);
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(and_should_not_match_if_right_component_does_not_match)
        {
            auto filter = krabs::predicates::and_filter(krabs::predicates::any_event, krabs::predicates::no_event);
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(or_should_match_an_event_if_left_component_matches)
        {
            auto filter = krabs::predicates::or_filter(krabs::predicates::any_event, krabs::predicates::no_event);
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(or_should_match_an_event_if_right_component_matches)
        {
            auto filter = krabs::predicates::or_filter(krabs::predicates::no_event, krabs::predicates::any_event);
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(or_should_match_an_event_if_both_components_match)
        {
            auto filter = krabs::predicates::or_filter(krabs::predicates::any_event, krabs::predicates::any_event);
            Assert::IsTrue(filter(record, trace_context));

            auto filter2 = krabs::predicates::or_filter(krabs::predicates::id_is(7397), krabs::predicates::version_is(1));
            Assert::IsTrue(filter2(record, trace_context));
        }

        TEST_METHOD(or_should_not_match_if_neither_component_matches)
        {
            auto filter = krabs::predicates::or_filter(krabs::predicates::no_event, krabs::predicates::no_event);
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(not_should_negate_value_of_component_filter)
        {
            auto filter1 = krabs::predicates::not_filter(krabs::predicates::any_event);
            Assert::IsFalse(filter1(record, trace_context));

            auto filter2 = krabs::predicates::not_filter(krabs::predicates::no_event);
            Assert::IsTrue(filter2(record, trace_context));

            auto filter3 = krabs::predicates::not_filter(krabs::predicates::id_is(7937));
            Assert::IsFalse(filter3(record, trace_context));

            auto filter4 = krabs::predicates::not_filter(krabs::predicates::version_is(2));
            Assert::IsTrue(filter4(record, trace_context));
        }
        TEST_METHOD(any_of_should_match_first)
        {
            auto item1 = krabs::predicates::any_event;
            auto item2 = krabs::predicates::no_event;
            auto filter = krabs::predicates::any_of({ &item1, &item2 });
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(any_of_should_match_last)
        {
            auto item1 = krabs::predicates::no_event;
            auto item2 = krabs::predicates::any_event;
            auto filter = krabs::predicates::any_of({ &item1, &item2 });
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(any_of_should_match_all)
        {
            auto item1 = krabs::predicates::any_event;
            auto item2 = krabs::predicates::any_event;
            auto filter = krabs::predicates::any_of({ &item1, &item2 });
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(any_of_should_not_match_any)
        {
            auto item1 = krabs::predicates::no_event;
            auto item2 = krabs::predicates::no_event;
            auto filter = krabs::predicates::any_of({ &item1, &item2 });
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(any_of_should_not_match_empty)
        {
            auto filter = krabs::predicates::any_of({});
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(all_of_should_match_all)
        {
            auto item1 = krabs::predicates::any_event;
            auto item2 = krabs::predicates::any_event;
            auto filter = krabs::predicates::all_of({ &item1, &item2 });
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(all_of_should_not_match_first)
        {
            auto item1 = krabs::predicates::any_event;
            auto item2 = krabs::predicates::no_event;
            auto filter = krabs::predicates::all_of({ &item1, &item2 });
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(all_of_should_not_match_last)
        {
            auto item1 = krabs::predicates::no_event;
            auto item2 = krabs::predicates::any_event;
            auto filter = krabs::predicates::all_of({ &item1, &item2 });
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(all_of_should_not_match_any)
        {
            auto item1 = krabs::predicates::no_event;
            auto item2 = krabs::predicates::no_event;
            auto filter = krabs::predicates::all_of({ &item1, &item2 });
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(all_of_should_not_match_empty)
        {
            auto filter = krabs::predicates::all_of({});
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(none_of_should_match_all)
        {
            auto item1 = krabs::predicates::no_event;
            auto item2 = krabs::predicates::no_event;
            auto filter = krabs::predicates::none_of({ &item1, &item2 });
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(none_of_should_match_empty)
        {
            auto filter = krabs::predicates::none_of({});
            Assert::IsTrue(filter(record, trace_context));
        }

        TEST_METHOD(none_of_should_not_match_first)
        {
            auto item1 = krabs::predicates::any_event;
            auto item2 = krabs::predicates::no_event;
            auto filter = krabs::predicates::none_of({ &item1, &item2 });
            Assert::IsFalse(filter(record, trace_context));
        }

        TEST_METHOD(none_of_should_not_match_last)
        {
            auto item1 = krabs::predicates::any_event;
            auto item2 = krabs::predicates::no_event;
            auto filter = krabs::predicates::none_of({ &item1, &item2 });
            Assert::IsFalse(filter(record, trace_context));
        }
    };
}