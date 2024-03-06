// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <krabs.hpp>

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// Converts a native GUID to a System::Guid
    /// </summary>
    inline System::Guid ConvertGuid(GUID guid)
    {
        return System::Guid(
            guid.Data1, guid.Data2, guid.Data3,
            guid.Data4[0], guid.Data4[1],
            guid.Data4[2], guid.Data4[3],
            guid.Data4[4], guid.Data4[5],
            guid.Data4[6], guid.Data4[7]);
    }

    /// <summary>
    /// Converts a System::Guid to a native GUID
    /// </summary>
    inline GUID ConvertGuid(System::Guid guid)
    {
        array<System::Byte>^ bytes = guid.ToByteArray();
        pin_ptr<System::Byte> data = &(bytes[0]);
        return *((GUID*)data);
    }

} } } }