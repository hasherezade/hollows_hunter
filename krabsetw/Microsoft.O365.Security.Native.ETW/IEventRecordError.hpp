// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include "IEventRecordMetadata.hpp"

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// Item passed to OnError handlers when an error is encountered
    /// handling an event on the worker thread.
    /// </summary>
    public interface struct IEventRecordError
    {
        /// <summary>
        /// Returns a string representing a message about the
        /// error that was encountered in the EventRecord.
        /// </summary>
        property System::String^ Message { System::String^ get(); }

        /// <summary>
        /// Returns an object representing metadata about the
        /// record that was being processed when the error was
        /// encountered.
        /// </summary>
        property IEventRecordMetadata^ Record { IEventRecordMetadata^ get(); }
    };

} } } }