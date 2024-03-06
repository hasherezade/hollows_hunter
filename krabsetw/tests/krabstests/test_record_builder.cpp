// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "CppUnitTest.h"
#include <krabs.hpp>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace krabstests
{
    TEST_CLASS(test_record_builder)
    {
    public:
        TEST_METHOD(should_remember_added_properties)
        {
            krabs::guid id(krabs::guid::random_guid());
            krabs::testing::record_builder builder(id, krabs::id(1), krabs::version(1));
            builder.add_properties()
                (L"Foo", L"Value")
                (L"Bar", L"Value");

            Assert::AreEqual(builder.properties().size(), static_cast<size_t>(2));
            Assert::AreEqual(builder.properties().at(0).name(), std::wstring(L"Foo"));
            Assert::AreEqual(builder.properties().at(1).name(), std::wstring(L"Bar"));
        }

        TEST_METHOD(pack_should_throw_when_an_incomplete_record_is_built)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7942), krabs::version(1));
            builder.add_properties()
                (L"ClassName", L"FakeETWEventForRealz")
                (L"Message", L"This message is completely faked");

            Assert::ExpectException<std::invalid_argument>([&] {
                builder.pack();
            });
        }

        TEST_METHOD(pack_should_not_throw_when_a_complete_record_is_built)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7942), krabs::version(1));

            builder.add_properties()
                (L"ClassName", L"FakeETWEventForRealz")
                (L"MethodName", L"asdf")
                (L"WorkflowGuid", L"asdfasdfasdf")
                (L"Message", L"This message is completely faked")
                (L"JobData", L"asdfasdf")
                (L"ActivityName", L"asaaa")
                (L"ActivityGuid", L"aaaaa")
                (L"Parameters", L"asfd");

            // call it and see if it throws.
            builder.pack();
        }

        TEST_METHOD(pack_should_throw_when_property_type_mismatched_with_schema)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7942), krabs::version(1));

            builder.add_properties()
                (L"ClassName", 45);

            Assert::ExpectException<std::invalid_argument>([&] {
                builder.pack();
            });
        }

        TEST_METHOD(pack_incomplete_should_not_throw_when_incomplete_record_built)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7942), krabs::version(1));

            builder.add_properties()
                (L"ClassName", L"FakeETWEventForRealz")
                (L"Message", L"This message is completely faked");

            // Call and see if it throws.
            builder.pack_incomplete();
        }

        TEST_METHOD(pack_incomplete_should_fill_enough_bytes_to_enable_reading_props_when_incomplete)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7942), krabs::version(1));

            builder.add_properties()
                (L"ClassName", L"FClassName")
                // Note: skips a few properties to so we can be sure we're padding the buffer
                (L"Message", L"Fake message");

            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            Assert::AreEqual(parser.parse<std::wstring>(L"ClassName"), std::wstring(L"FClassName"));
            Assert::AreEqual(parser.parse<std::wstring>(L"Message"), std::wstring(L"Fake message"));
        }

        TEST_METHOD(pack_incomplete_should_fill_enough_bytes_for_nonstring_types_when_incomplete)
        {
            krabs::guid wininet(L"{43D1A55C-76D6-4F7E-995C-64C711E5CAFE}");
            krabs::testing::record_builder builder(wininet, krabs::id(1057), krabs::version(0));

            builder.add_properties()
                (L"URL", "https://microsoft.com")
                (L"Status", (unsigned int)300);

            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            Assert::AreEqual(parser.parse<unsigned int>(L"Status"), (unsigned int)300);
            Assert::AreEqual(parser.parse<std::string>(L"URL"), std::string("https://microsoft.com"));
        }

        TEST_METHOD(pack_incomplete_should_correctly_handle_no_set_props)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7942), krabs::version(1));
            auto record = builder.pack_incomplete();
        }

        TEST_METHOD(pack_incomplete_should_correctly_handle_sid_in_event)
        {
            krabs::guid logon(L"{199FE037-2B82-40A9-82AC-E1D46C792B99}");
            krabs::testing::record_builder builder(logon, krabs::id(301), krabs::version(0));
            builder.add_properties()
                (L"TargetUserName", L"")
                (L"LogonType", (uint32_t)5);

            auto record = builder.pack_incomplete();

            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);
            Assert::AreEqual(parser.parse<uint32_t>(L"LogonType"), (uint32_t)5);
        }

        TEST_METHOD(pack_should_include_extended_data)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7942), krabs::version(1));
            // Random GUID
            builder.add_container_id_extended_data(krabs::guid(L"{86E2A814-8893-431D-A1DC-F44931D6B99A}"));
            
            // Have to hold onto the record instance so that the data buffers don't get deleted.
            auto synth_record = builder.pack_incomplete();
            const EVENT_RECORD& record = synth_record;

            // USHORT has template specialization issues, so use uint.
            Assert::AreEqual((unsigned int)record.ExtendedDataCount, 1u);
            Assert::IsNotNull(record.ExtendedData);
        }

        TEST_METHOD(pack_should_correctly_handle_no_extended_data)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7942), krabs::version(1));
            
            // Have to hold onto the record instance so that the data buffers don't get deleted.
            auto synth_record = builder.pack_incomplete();
            const EVENT_RECORD& record = synth_record;
            
            // USHORT has template specialization issues, so use uint.
            Assert::AreEqual((unsigned int)record.ExtendedDataCount, 0u);
            Assert::IsNull(record.ExtendedData);
        }

        TEST_METHOD(pack_should_correctly_handle_multiple_extended_data)
        {
            // This assumes that the builder isn't enforcing semantic constraints like "you can't 
            // have more than one container ID extended data item in the same event". Which is
            // probably true for events you'd get from the real API, but we're going to exploit the
            // loophole to test the "multiple extended data" case.
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7942), krabs::version(1));
            // Random GUID
            builder.add_container_id_extended_data(krabs::guid(L"{86E2A814-8893-431D-A1DC-F44931D6B99A}"));
            builder.add_container_id_extended_data(krabs::guid(L"{86E2A814-8893-431D-A1DC-F44931D6B99A}"));

            // Have to hold onto the record instance so that the data buffers don't get deleted.
            auto synth_record = builder.pack_incomplete();
            const EVENT_RECORD& record = synth_record;

            // USHORT has template specialization issues, so use uint.
            Assert::AreEqual((unsigned int)record.ExtendedDataCount, 2u);
            Assert::IsNotNull(record.ExtendedData);

            // Sanity check
            Assert::AreEqual((unsigned int)record.ExtendedData[0].ExtType, (unsigned int)EVENT_HEADER_EXT_TYPE_CONTAINER_ID);
            Assert::AreEqual((unsigned int)record.ExtendedData[1].ExtType, (unsigned int)EVENT_HEADER_EXT_TYPE_CONTAINER_ID);
        }

        TEST_METHOD(container_id_should_be_read_correctly_after_packing)
        {
            // Randomly generated GUID
            const krabs::guid CONTAINER_GUID(L"{86E2A814-8893-431D-A1DC-F44931D6B99A}");

            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7942), krabs::version(1));
            builder.add_container_id_extended_data(CONTAINER_GUID);
            
            // Have to hold onto the record instance so that the data buffers don't get deleted.
            auto synth_record = builder.pack_incomplete();
            const EVENT_RECORD& record = synth_record;

            // USHORT has template specialization issues, so use uint.
            Assert::AreEqual((unsigned int)record.ExtendedDataCount, 1u);
            Assert::IsNotNull(record.ExtendedData);
            
            auto& extended_data = record.ExtendedData[0];
            Assert::AreEqual((unsigned int)extended_data.ExtType, (unsigned int)EVENT_HEADER_EXT_TYPE_CONTAINER_ID);
            Assert::AreEqual((size_t)extended_data.DataSize, krabs::testing::extended_data_builder::GUID_STRING_LENGTH_NO_BRACES);
            
            auto parsed_guid = krabs::guid_parser::parse_guid(
                reinterpret_cast<const char*>(extended_data.DataPtr), 
                extended_data.DataSize);

            // Check that the right GUID came out.
            Assert::IsTrue(CONTAINER_GUID == krabs::guid(parsed_guid));
        }

        private:
            krabs::schema_locator schema_locator_;
    };
}