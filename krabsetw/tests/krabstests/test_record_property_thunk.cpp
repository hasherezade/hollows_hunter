// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "CppUnitTest.h"
#include <krabs.hpp>
#include <in6addr.h>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace Microsoft
{
    namespace VisualStudio
    {
        namespace CppUnitTestFramework
        {
            template<> std::wstring ToString<_TDH_IN_TYPE>(const _TDH_IN_TYPE& t) { RETURN_WIDE_STRING(t); }

            template<> std::wstring ToString<std::vector<BYTE>>(const std::vector<BYTE>& t)
            {
                return std::wstring(reinterpret_cast<const wchar_t*>(&t[0]), t.size());
            }
        }
    }
}

namespace krabstests
{
    TEST_CLASS(test_record_property_thunk)
    {
    public:

        TEST_METHOD(should_remember_the_name_that_was_given_to_it)
        {
            std::wstring expected_name(L"some silly name");
            krabs::testing::record_property_thunk thunk(expected_name, L"hello");
            Assert::AreEqual(thunk.name(), expected_name);
        }

        TEST_METHOD(should_pack_bytes_for_unicode_strings)
        {
            krabs::testing::record_property_thunk thunk(L"prop1", L"ab");
            std::vector<BYTE> expected_bytes{ 'a', '\0', 'b', '\0', '\0', '\0' };
            Assert::AreEqual(thunk.bytes(), expected_bytes);
            Assert::AreEqual(thunk.type(), TDH_INTYPE_UNICODESTRING);
        }

        TEST_METHOD(should_pack_bytes_for_ANSI_strings)
        {
            krabs::testing::record_property_thunk thunk(L"prop1", "cd");
            std::vector<BYTE> expected_bytes{ 'c', 'd', '\0' };
            Assert::AreEqual(thunk.bytes(), expected_bytes);
            Assert::AreEqual(thunk.type(), TDH_INTYPE_ANSISTRING);
        }

        TEST_METHOD(should_pack_bytes_for_character)
        {
            krabs::testing::record_property_thunk thunk(L"prop", 'e');
            std::vector<BYTE> expected_bytes{ 'e' };
            Assert::AreEqual(thunk.bytes(), expected_bytes);
            Assert::AreEqual(thunk.type(), TDH_INTYPE_INT8);
        }

        TEST_METHOD(should_pack_bytes_for_unsigned_character)
        {
            krabs::testing::record_property_thunk thunk(L"prop", (unsigned char)'f');
            std::vector<BYTE> expected_bytes{ 'f' };
            Assert::AreEqual(thunk.bytes(), expected_bytes);
            Assert::AreEqual(thunk.type(), TDH_INTYPE_UINT8);
        }

        TEST_METHOD(should_pack_bytes_for_shorts)
        {
            krabs::testing::record_property_thunk thunk(L"prop", static_cast<short>(0x1234));
            std::vector<BYTE> expected_bytes{ 0x34, 0x12 };
            Assert::AreEqual(thunk.bytes(), expected_bytes);
            Assert::AreEqual(thunk.type(), TDH_INTYPE_INT16);
        }

        TEST_METHOD(should_pack_bytes_for_unsigned_shorts)
        {
            krabs::testing::record_property_thunk thunk(L"prop", static_cast<unsigned short>(0x2345));
            std::vector<BYTE> expected_bytes{ 0x45, 0x23 };
            Assert::AreEqual(thunk.bytes(), expected_bytes);
            Assert::AreEqual(thunk.type(), TDH_INTYPE_UINT16);
        }

        TEST_METHOD(should_pack_bytes_for_ints)
        {
            krabs::testing::record_property_thunk thunk(L"prop", 0x12345678);
            std::vector<BYTE> expected_bytes{ 0x78, 0x56, 0x34, 0x12 };
            Assert::AreEqual(thunk.bytes(), expected_bytes);
            Assert::AreEqual(thunk.type(), TDH_INTYPE_INT32);
        }

        TEST_METHOD(should_pack_bytes_for_unsigned_ints)
        {
            krabs::testing::record_property_thunk thunk(L"prop", (unsigned int)0x12345678);
            std::vector<BYTE> expected_bytes{ 0x78, 0x56, 0x34, 0x12 };
            Assert::AreEqual(thunk.bytes(), expected_bytes);
            Assert::AreEqual(thunk.type(), TDH_INTYPE_UINT32);
        }

        TEST_METHOD(should_pack_bytes_for_long_longs)
        {
            krabs::testing::record_property_thunk thunk(L"prop", 0x1234567823456789);
            std::vector<BYTE> expected_bytes{ 0x89, 0x67, 0x45, 0x23, 0x78, 0x56, 0x34, 0x12 };
            Assert::AreEqual(thunk.bytes(), expected_bytes);
            Assert::AreEqual(thunk.type(), TDH_INTYPE_INT64);
        }

        TEST_METHOD(should_pack_bytes_for_unsigned_long_longs)
        {
            krabs::testing::record_property_thunk thunk(L"prop", (unsigned long long)0x1234567823456789);
            std::vector<BYTE> expected_bytes{ 0x89, 0x67, 0x45, 0x23, 0x78, 0x56, 0x34, 0x12 };
            Assert::AreEqual(thunk.bytes(), expected_bytes);
            Assert::AreEqual(thunk.type(), TDH_INTYPE_UINT64);
        }

        TEST_METHOD(should_pack_bytes_for_floats)
        {
            krabs::testing::record_property_thunk thunk(L"prop", 1.2f);
            // I seriously don't have a good intuition for
            // how floats are packed into memory, so I'm not
            // even gonna try. /)_(\.
            // TODO: @zbrown How are floats packed?
            Assert::AreEqual(thunk.bytes().size(), static_cast<unsigned long long>(4)); 
            Assert::AreEqual(thunk.type(), TDH_INTYPE_FLOAT);
        }

        TEST_METHOD(should_pack_bytes_for_doubles)
        {
            krabs::testing::record_property_thunk thunk(L"prop", (double)1.2);
            // I seriously don't have a good intuition for
            // how doubles are packed into memory, so I'm not
            // even gonna try. /)_(\.
            // TODO: @zbrown How are floats packed?
            Assert::AreEqual(thunk.bytes().size(), static_cast<unsigned long long>(8));
            Assert::AreEqual(thunk.type(), TDH_INTYPE_DOUBLE);
        }

        TEST_METHOD(should_pack_bytes_for_boolean)
        {
            krabs::testing::record_property_thunk thunk(L"prop", true);
            std::vector<BYTE> expected_bytes{ 0x01, 0x00, 0x00, 0x00 };
            Assert::AreEqual(thunk.bytes(), expected_bytes);
            Assert::AreEqual(thunk.type(), TDH_INTYPE_BOOLEAN);
        }

        TEST_METHOD(should_pack_bytes_for_binary_blobs)
        {
            in6_addr ip = { 0x40
                , 0x41
                , 0x42
                , 0x43
                , 0x44
                , 0x45
                , 0x46
                , 0x47
                , 0x48
                , 0x49
                , 0x4A
                , 0x4B
                , 0x4C
                , 0x4D
                , 0x4E
                , 0x4F
            };

            auto bin = krabs::make_binary(ip.u.Byte, sizeof(in6_addr));

            krabs::testing::record_property_thunk thunk(L"prop", bin);
            std::vector<BYTE> expected_bytes{ 0x40, 0x41
                , 0x42, 0x43
                , 0x44, 0x45
                , 0x46, 0x47
                , 0x48, 0x49
                , 0x4A, 0x4B
                , 0x4C, 0x4D
                , 0x4E, 0x4F };

            Assert::AreEqual(thunk.bytes(), expected_bytes);
            Assert::AreEqual(thunk.type(), TDH_INTYPE_BINARY);
        }

        TEST_METHOD(should_pack_bytes_for_SID)
        {
            SID sid = { 0x01 // revision
                , 0x02 // sub authority count
                , 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 // identifier authority
                , 0xAABBCCDD // sub authority
            };

            krabs::testing::record_property_thunk thunk(L"prop", sid);
            std::vector<BYTE> expected_bytes{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xDD, 0xCC, 0xBB, 0xAA };
            Assert::AreEqual(thunk.bytes(), expected_bytes);
            Assert::AreEqual(thunk.type(), TDH_INTYPE_SID);
        }

        TEST_METHOD(should_pack_bytes_for_hexint)
        {
            krabs::hexint32 value(0x0102ABCD);
            krabs::testing::record_property_thunk thunk(L"prop", value);

            std::vector<BYTE> expected_bytes{ 0xCD, 0xAB, 0x02, 0x01 };
            Assert::AreEqual(thunk.bytes(), expected_bytes);
            Assert::AreEqual(thunk.type(), TDH_INTYPE_HEXINT32);
        }

        TEST_METHOD(should_pack_bytes_for_long_hexint)
        {
            krabs::hexint64 value(0x0102ABCDEF030435);
            krabs::testing::record_property_thunk thunk(L"prop", value);

            std::vector<BYTE> expected_bytes{ 0x35, 0x04, 0x03, 0xEF, 0xCD, 0xAB, 0x02, 0x01 };
            Assert::AreEqual(thunk.bytes(), expected_bytes);
            Assert::AreEqual(thunk.type(), TDH_INTYPE_HEXINT64);
        }
    };
}
