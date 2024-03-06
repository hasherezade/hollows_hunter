// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "CppUnitTest.h"
#include <krabs.hpp>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace krabstests
{
    TEST_CLASS(test_parse_types)
    {
    public:
        TEST_METHOD(counted_string)
        {
            // the counted string is len 5 (10 bytes), pack(1) and doesn't include ! chars
            const wchar_t* counted_string_data = L"\x0A" L"ABCDE!!!!!";
            auto cs = reinterpret_cast<const krabs::counted_string*>(counted_string_data);

            Assert::IsTrue(cs->size_ == 0x0A);
            Assert::IsTrue(cs->string_[0] == 'A');
        }
    };
}