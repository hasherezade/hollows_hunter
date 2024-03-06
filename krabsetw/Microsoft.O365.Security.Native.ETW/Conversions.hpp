// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <type_traits>

using namespace System;
using namespace System::Runtime::InteropServices;

namespace Microsoft::O365::Security::ETW {

// Converts a CLR List<T> of arithmetic types to a corresponding std::vector<T>
template <typename T, typename std::enable_if_t<std::is_arithmetic<T>::value, T> = 0>
std::vector<T> to_vector(List<T>^ list)
{
    std::vector<T> vector(list->Count);

    for each (auto item in list)
    {
        vector.push_back(item);
    }

    return vector;
}

}