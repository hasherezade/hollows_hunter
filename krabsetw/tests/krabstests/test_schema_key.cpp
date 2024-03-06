// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "CppUnitTest.h"
#include <krabs.hpp>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace krabstests
{
    TEST_CLASS(test_schema_key)
    {
    private:
        const krabs::guid provider1;
        const krabs::guid provider2;
        const std::hash<krabs::schema_key> hash;

        krabs::schema_key GetKeyForRecord(
            const krabs::guid& providerId,
            const size_t id,
            const size_t version,
            const size_t opcode,
            const size_t level)
        {
            krabs::testing::record_builder builder(providerId, id, version, opcode, level);
            auto record = builder.create_stub_record();

            return krabs::schema_key{ EVENT_RECORD(record) };
        }

    public:
        test_schema_key() :
            provider1(L"{88154140-f63a-4028-8826-b0028614d67b}"),
            provider2(L"{41ee9f36-5a4e-4138-bc0e-2141a84eb089}"),
            hash()
        {
        }

        TEST_METHOD(should_be_equal_when_uninitialized)
        {
            const EVENT_RECORD eventRecord = {};
            const krabs::schema_key key1{ eventRecord };
            const krabs::schema_key key2{ eventRecord };

            Assert::IsTrue(key1 == key2);
        }
        TEST_METHOD(should_hash_same_when_uninitialized)
        {
            const EVENT_RECORD eventRecord = {};
            const krabs::schema_key key1{ eventRecord };
            const krabs::schema_key key2{ eventRecord };

            // When a defect is present, this may only fail in Release builds
            // Ref: https://github.com/microsoft/krabsetw/issues/139
            Assert::IsTrue(hash(key1) == hash(key2));
        }
        TEST_METHOD(should_be_equal_when_identical_property_values)
        {
            auto key1 = GetKeyForRecord(provider1, 1, 2, 3, 4);
            auto key2 = GetKeyForRecord(provider1, 1, 2, 3, 4);

            Assert::IsTrue(key1 == key2);
        }
        TEST_METHOD(should_hash_same_when_identical_property_values)
        {
            auto key1 = GetKeyForRecord(provider1, 1, 2, 3, 4);
            auto key2 = GetKeyForRecord(provider1, 1, 2, 3, 4);

            Assert::IsTrue(hash(key1) == hash(key2));
        }
        TEST_METHOD(should_not_be_equal_when_providerid_differs)
        {
            auto key1 = GetKeyForRecord(provider1, 1, 2, 3, 4);
            auto key2 = GetKeyForRecord(provider2, 1, 2, 3, 4);

            Assert::IsFalse(key1 == key2);
        }
        TEST_METHOD(should_not_hash_same_when_providerid_differs)
        {
            auto key1 = GetKeyForRecord(provider1, 1, 2, 3, 4);
            auto key2 = GetKeyForRecord(provider2, 1, 2, 3, 4);

            Assert::IsFalse(hash(key1) == hash(key2));
        }
        TEST_METHOD(should_not_be_equal_when_id_differs)
        {
            auto key1 = GetKeyForRecord(provider1, 1, 2, 3, 4);
            auto key2 = GetKeyForRecord(provider1, 2, 2, 3, 4);

            Assert::IsFalse(key1 == key2);
        }
        TEST_METHOD(should_not_hash_same_when_id_differs)
        {
            auto key1 = GetKeyForRecord(provider1, 1, 2, 3, 4);
            auto key2 = GetKeyForRecord(provider1, 2, 2, 3, 4);

            Assert::IsFalse(hash(key1) == hash(key2));
        }
        TEST_METHOD(should_not_be_equal_when_version_differs)
        {
            auto key1 = GetKeyForRecord(provider1, 1, 2, 3, 4);
            auto key2 = GetKeyForRecord(provider1, 1, 3, 3, 4);

            Assert::IsFalse(key1 == key2);
        }
        TEST_METHOD(should_not_hash_same_when_version_differs)
        {
            auto key1 = GetKeyForRecord(provider1, 1, 2, 3, 4);
            auto key2 = GetKeyForRecord(provider1, 1, 3, 3, 4);

            Assert::IsFalse(hash(key1) == hash(key2));
        }
        TEST_METHOD(should_not_be_equal_when_opcode_differs)
        {
            auto key1 = GetKeyForRecord(provider1, 1, 2, 3, 4);
            auto key2 = GetKeyForRecord(provider1, 1, 2, 4, 4);

            Assert::IsFalse(key1 == key2);
        }
        TEST_METHOD(should_not_hash_same_when_opcode_differs)
        {
            auto key1 = GetKeyForRecord(provider1, 1, 2, 3, 4);
            auto key2 = GetKeyForRecord(provider1, 1, 2, 4, 4);

            Assert::IsFalse(hash(key1) == hash(key2));
        }
        TEST_METHOD(should_not_be_equal_when_level_differs)
        {
            auto key1 = GetKeyForRecord(provider1, 1, 2, 3, 4);
            auto key2 = GetKeyForRecord(provider1, 1, 2, 3, 5);

            Assert::IsFalse(key1 == key2);
        }
        TEST_METHOD(should_not_hash_same_when_level_differs)
        {
            auto key1 = GetKeyForRecord(provider1, 1, 2, 3, 4);
            auto key2 = GetKeyForRecord(provider1, 1, 2, 3, 5);

            Assert::IsFalse(hash(key1) == hash(key2));
        }
    };
}