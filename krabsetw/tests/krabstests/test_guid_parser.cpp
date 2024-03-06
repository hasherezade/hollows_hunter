// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "CppUnitTest.h"
#include <krabs.hpp>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace krabstests
{
    TEST_CLASS(test_guid_parser)
    {
    public:
        TEST_METHOD(should_parse_single_octet)
        {
            // Arbitrary value
            const char* octet = "9D";
            unsigned char value = 0;
            Assert::IsTrue(krabs::guid_parser::hex_octet_to_byte(octet, value));
            Assert::AreEqual((unsigned int)value, 0x9Du);
        }

        TEST_METHOD(octet_parsing_should_fail_invalid_hex_chars)
        {
            // Arbitrary value
            const char* octet = "5G";
            unsigned char value = 0;
            Assert::IsFalse(krabs::guid_parser::hex_octet_to_byte(octet, value));
        }

        TEST_METHOD(octet_parsing_should_be_case_insensitive)
        {
            // Arbitrary value
            const char* lowercase = "ab";
            const char* uppercase = "AB";

            unsigned char lowercase_value = 0;
            unsigned char uppercase_value = 0;

            Assert::IsTrue(krabs::guid_parser::hex_octet_to_byte(lowercase, lowercase_value));
            Assert::IsTrue(krabs::guid_parser::hex_octet_to_byte(uppercase, uppercase_value));
            Assert::AreEqual((unsigned int)lowercase_value, 0xABu);
            Assert::AreEqual((unsigned int)uppercase_value, 0xABu);
        }

        TEST_METHOD(should_parse_hex_octet_string)
        {
            const char* str = "1234ABCD";
            unsigned char output[4] = { 0 };

            Assert::IsTrue(krabs::guid_parser::hex_string_to_bytes(str, output, sizeof(output)));
            Assert::AreEqual((unsigned int)output[0], 0x12u);
            Assert::AreEqual((unsigned int)output[1], 0x34u);
            Assert::AreEqual((unsigned int)output[2], 0xABu);
            Assert::AreEqual((unsigned int)output[3], 0xCDu);
        }

        TEST_METHOD(should_not_parse_extra_octets)
        {
            const char* str = "5678CDEF";
            unsigned char output[4] = { 0 };

            Assert::IsTrue(krabs::guid_parser::hex_string_to_bytes(str, output, 3));
            Assert::AreEqual((unsigned int)output[0], 0x56u);
            Assert::AreEqual((unsigned int)output[1], 0x78u);
            Assert::AreEqual((unsigned int)output[2], 0xCDu);
            Assert::AreEqual((unsigned int)output[3], 0x00u);
        }

        TEST_METHOD(multi_octet_parsing_should_parse_single_octet)
        {
            const char* str = "2B";
            unsigned char output = 0;

            Assert::IsTrue(krabs::guid_parser::hex_string_to_bytes(str, &output, 1));
            Assert::AreEqual((unsigned int)output, 0x2Bu);
        }

        TEST_METHOD(multi_octet_parsing_should_fail_on_invalid_hex_char)
        {
            const char* str1 = "ABCDEF-123";
            const char* str2 = "abcdefghij";
            const char* str3 = "abcdef123\0";
            unsigned char output[5] = { 0 };

            Assert::IsFalse(krabs::guid_parser::hex_string_to_bytes(str1, output, 5));
            Assert::IsFalse(krabs::guid_parser::hex_string_to_bytes(str2, output, 5));
            Assert::IsFalse(krabs::guid_parser::hex_string_to_bytes(str3, output, 5));
        }

        TEST_METHOD(uint_parsing_should_parse)
        {
            const char* str = "12345678";
            uint32_t value_32 = 0;
            uint16_t value_16 = 0;
            
            Assert::IsTrue(krabs::guid_parser::hex_string_to_number(str, value_32));
            Assert::IsTrue(krabs::guid_parser::hex_string_to_number(str, value_16));

            Assert::AreEqual(value_32, 0x12345678u);
            Assert::AreEqual((unsigned int)value_16, 0x1234u);
        }

        TEST_METHOD(uint_parsing_should_fail_on_invalid_char)
        {
            const char* str = "1234567-";
            unsigned int value = 0;
            Assert::IsFalse(krabs::guid_parser::hex_string_to_number(str, value));
        }

        TEST_METHOD(should_parse_guid)
        {
            const char* guid_str = "73d28a4b-3fdd-49a5-9ac2-6e3b15a4196a";
            GUID guid = krabs::guid_parser::parse_guid(guid_str, 36);
            Assert::IsTrue(guid == krabs::guid(L"{73d28a4b-3fdd-49a5-9ac2-6e3b15a4196a}"));
        }

        TEST_METHOD(should_parse_case_insensitively)
        {
            const char* guid_str = "F81DC00B-B6E6-4E94-B676-77EC5E93CA12";
            GUID guid = krabs::guid_parser::parse_guid(guid_str, 36);
            Assert::IsTrue(guid == krabs::guid(L"{F81DC00B-B6E6-4E94-B676-77EC5E93CA12}"));
        }

        TEST_METHOD(should_parse_without_null_terminator)
        {
            const char* guid_str = "e3801e83-3ea3-4437-95ea-0f854b7d783f";
            const char buffer[36] = { 0 };
            memcpy((void*)buffer, guid_str, 36);

            GUID guid = krabs::guid_parser::parse_guid(buffer, 36);
            Assert::IsTrue(guid == krabs::guid(L"{e3801e83-3ea3-4437-95ea-0f854b7d783f}"));
        }

        TEST_METHOD(should_fail_with_incorrect_length)
        {
            const char* guid_str = "a1219928-a27f-4026-a3ce-b7d3a6dcb633";
            Assert::ExpectException<std::runtime_error>([guid_str]() 
                {
                    GUID guid = krabs::guid_parser::parse_guid(guid_str, 37);
                });
        }

        TEST_METHOD(should_fail_with_incorrect_delimiter)
        {
            const char* guid_str = "5deadd42 01d5-45f5-b3e2-3fdb5bb63f10";
            Assert::ExpectException<std::runtime_error>([guid_str]()
                {
                    GUID guid = krabs::guid_parser::parse_guid(guid_str, 36);
                });
        }

        TEST_METHOD(should_fail_with_incorrect_segment)
        {
            const char* guid_str = "1c92843-b85e3-4257-9b0c-f03350bb2253";
            Assert::ExpectException<std::runtime_error>([guid_str]()
                {
                    GUID guid = krabs::guid_parser::parse_guid(guid_str, 36);
                });
        }
    };
}