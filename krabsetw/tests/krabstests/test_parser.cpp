// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "CppUnitTest.h"
#include <krabs.hpp>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace krabstests
{
    TEST_CLASS(test_parser)
    {
    public:

        TEST_METHOD(should_return_correct_count_of_props_when_enumerating)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7942), krabs::version(1));

            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            // The number 8 here comes from the definition of the event in ETW -- we don't have control
            // of this.
            auto props = parser.properties();
            Assert::AreEqual((size_t)std::distance(props.begin(), props.end()), (size_t)8);
        }

#if NDEBUG
        TEST_METHOD(parse_should_not_throw_when_requesting_wrong_property_type_in_release)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7937), krabs::version(1));

            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            // note, this would be a corrupted result
            parser.parse<std::string>(L"ContextInfo");
        }

        TEST_METHOD(try_parse_should_not_throw_when_requesting_wrong_property_type_in_release)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7937), krabs::version(1));

            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            // note, this would be a corrupted result
            std::string result;
            Assert::IsTrue(parser.try_parse(L"ContextInfo", result));
        }

        TEST_METHOD(parse_should_throw_when_requesting_property_with_type_size_mismatch_in_release)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7937), krabs::version(1));

            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            Assert::ExpectException<std::runtime_error>([&]() { parser.parse<int>(L"ContextInfo"); });
        }

        TEST_METHOD(try_parse_should_return_false_when_requesting_property_with_type_size_mismatch_in_release)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7937), krabs::version(1));

            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            int result = 0;
            Assert::IsFalse(parser.try_parse(L"ContextInfo", result));
        }
#else
        TEST_METHOD(parse_should_throw_type_mismatch_when_requesting_property_with_wrong_type_in_debug)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7937), krabs::version(1));

            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            Assert::ExpectException<krabs::type_mismatch_assert>([&]() { parser.parse<std::string>(L"ContextInfo"); });
        }

        TEST_METHOD(try_parse_should_throw_mismatch_when_requesting_property_of_wrong_type_in_debug)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7937), krabs::version(1));

            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            std::string result;
            Assert::ExpectException<krabs::type_mismatch_assert>([&]() { parser.try_parse(L"ContextInfo", result); });
        }

        TEST_METHOD(parse_binary_should_return_field_bytes)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7937), krabs::version(1));
            builder.add_properties()(L"ContextInfo", L"Testing");

            auto record = builder.pack_incomplete();
            krabs::schema_locator schema_locator;
            krabs::schema schema(record, schema_locator);
            krabs::parser parser(schema);

            // note: binary doesn't type check
            auto data = parser.parse<krabs::binary>(L"ContextInfo");
            Assert::AreEqual((size_t)16, data.bytes().size());
            Assert::AreEqual((BYTE)'T', data.bytes()[0]);
        }
#endif

        TEST_METHOD(parse_unicode_string_should_work_when_unicode_string_property_is_last_and_not_null_terminated)
        {
            std::wstring expectedUrl(L"https://www.foo.com/api/v1/health/check");

            krabs::guid httpsys(L"{dd5ef90a-6398-47a4-ad34-4dcecdef795f}");
            // httpsys: parse event
            krabs::testing::record_builder builder(httpsys, krabs::id(2), 0U, 12, 1, true);
            builder.add_properties()
                (L"Url", expectedUrl);

            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            auto url = parser.parse<std::wstring>(L"Url");

            Assert::AreEqual(expectedUrl, url);
        }

        TEST_METHOD(parse_unicode_string_should_work_when_unicode_string_property_is_last_and_not_null_terminated_when_previous_properties_were_parsed)
        {
            std::wstring expectedUrl;

            krabs::guid httpsys(L"{dd5ef90a-6398-47a4-ad34-4dcecdef795f}");
            // httpsys: parse event
            krabs::testing::record_builder builder(httpsys, krabs::id(2), 0U, 12, 1, true);
            builder.add_properties()
                (L"Url", expectedUrl);

            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            auto requestobj = parser.parse<krabs::binary>(L"RequestObj");
            auto httpverb = parser.parse<krabs::binary>(L"HttpVerb");
            auto url = parser.parse<std::wstring>(L"Url");

            Assert::AreEqual(expectedUrl, url);
        }

        private:
            krabs::schema_locator schema_locator_;
    };
}