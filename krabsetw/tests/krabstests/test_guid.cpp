// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "CppUnitTest.h"
#include <krabs.hpp>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace krabstests
{
    TEST_CLASS(test_guid)
    {
    private:
        const krabs::guid guid1a;
        const krabs::guid guid1b;
        const krabs::guid guid2;
        const std::hash<krabs::guid> hash;

    public:
        test_guid() :
            guid1a(L"{88154140-f63a-4028-8826-b0028614d67b}"),
            guid1b(L"{88154140-f63a-4028-8826-b0028614d67b}"),
            guid2(L"{41ee9f36-5a4e-4138-bc0e-2141a84eb089}"),
            hash()
        {
        }

        TEST_METHOD(should_be_equal_when_identical)
        {
            Assert::IsTrue(guid1a == guid1b);
        }
        TEST_METHOD(should_hash_same_when_identical)
        {
            Assert::IsTrue(hash(guid1a) == hash(guid1b));
        }
        TEST_METHOD(should_not_be_equal_when_different)
        {
            Assert::IsFalse(guid1a == guid2);
        }
        TEST_METHOD(should_not_hash_same_when_different)
        {
            Assert::IsFalse(hash(guid1a) == hash(guid2));
        }
    };
}