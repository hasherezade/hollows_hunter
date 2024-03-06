// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include "IEventRecordError.hpp"
#include "IEventRecordMetadata.hpp"

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// Item passed to OnError handlers when an error is encountered
    /// handling an event on the worker thread.
    /// </summary>
    public ref struct EventRecordError : public IEventRecordError
    {
    private:
        initonly System::String^ msg_;
        initonly IEventRecordMetadata^ record_;

    public:
        /// <summary>
        /// Returns a string representing a message about the
        /// error that was encountered in the EventRecord.
        /// </summary>
        virtual property System::String^ Message {
            System::String^ get() {
                return msg_;
            }
        }

        /// <summary>
        /// Returns an object representing metadata about the
        /// record that was being processed when the error was
        /// encountered.
        /// </summary>
        virtual property IEventRecordMetadata^ Record {
            IEventRecordMetadata^ get() {
                return record_;
            }
        }

    internal:
        EventRecordError(
            System::String^ message,
            IEventRecordMetadata^ record)
            : msg_(message)
            , record_(record)
        { }
    };

} } } }