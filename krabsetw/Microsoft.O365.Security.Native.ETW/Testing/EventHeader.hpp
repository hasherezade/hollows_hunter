// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft { namespace O365 { namespace Security { namespace ETW { namespace Testing {

    public enum class EventHeaderFlags : uint16_t
    {
        EXTENDED_INFO        = 0x0001,
        PRIVATE_SESSION      = 0x0002,
        STRING_ONLY          = 0x0004,
        TRACE_MESSAGE        = 0x0008,
        NO_CPUTIME           = 0x0010,
        HEADER_32_BIT        = 0x0020,
        HEADER_64_BIT        = 0x0040,
        CLASSIC_HEADER       = 0x0100,
        PROCESSOR_INDEX      = 0x0200
    };

    /// <summary>
    /// Provides access to the EVENT_HEADER element of a synthetic
    /// event record.
    /// </summary>
    public ref class EventHeader {
    public:
        EventHeader(EVENT_HEADER *header);

        /// <summary>
        /// Provides access to the Flags field of the EventHeader.
        /// </summary>
        property unsigned short Flags {
            unsigned short get() {
                return header_->Flags;
            }

            void set(unsigned short val) {
                header_->Flags = val;
            }
        }

    internal:
        EVENT_HEADER *header_;
    };

    // Implementation
    // ------------------------------------------------------------------------

    inline EventHeader::EventHeader(EVENT_HEADER *header)
    : header_(header)
    { }




} /* namespace Testing */ } /* namespace ETW */ } /* namespace Security */ } /* namespace O365 */ } /* namespace Microsoft */