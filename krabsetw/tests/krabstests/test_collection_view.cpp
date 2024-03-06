// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "CppUnitTest.h"
#include <krabs.hpp>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace krabstests
{
    TEST_CLASS(test_collection_view)
    {
    public:

        TEST_METHOD(should_iterate_vector)
        {
            std::vector<char> vect{ 1, 2, 3 };
            auto v = krabs::view(vect.begin(), vect.end());

            Assert::IsTrue(std::equal(v.begin(), v.end(), vect.begin()));
        }

        TEST_METHOD(should_iterate_std_string)
        {
            std::string s = "this is the std::string";
            auto v = krabs::view(s);

            Assert::IsTrue(std::equal(v.begin(), v.end(), s.begin()));
        }

        TEST_METHOD(should_iterate_std_wstring)
        {
            std::wstring s = L"this is the std::wstring";
            auto v = krabs::view(s);

            Assert::IsTrue(std::equal(v.begin(), v.end(), s.begin()));
        }

        TEST_METHOD(should_iterate_c_string)
        {
            const char* s = "this is the c string";
            std::string str(s);
            auto v = krabs::view(s, strlen(s));

            Assert::IsTrue(std::equal(v.begin(), v.end(), str.begin()));
        }

        TEST_METHOD(should_iterate_wide_c_string)
        {
            const wchar_t* s = L"this is the c wstring";
            std::wstring str(s);
            auto v = krabs::view(s, wcslen(s));

            Assert::IsTrue(std::equal(v.begin(), v.end(), str.begin()));
        }

        TEST_METHOD(should_iterate_char_array)
        {
            const char s[] = "this is the string array";
            std::string str(s);
            auto v = krabs::view(s, strlen(s));

            Assert::IsTrue(std::equal(v.begin(), v.end(), str.begin()));
        }

        TEST_METHOD(should_iterate_counted_string)
        {
            const wchar_t* data = L"\x34" L"this is the counted string";
            auto cs = (krabs::counted_string*)data;
            std::wstring str(cs->string_, cs->length());
            auto v = krabs::view(cs->string_, cs->length());

            Assert::IsTrue(std::equal(v.begin(), v.end(), str.begin()));
        }
    };
}