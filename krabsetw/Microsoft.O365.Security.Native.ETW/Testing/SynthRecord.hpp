// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <krabs.hpp>
#include "../Guid.hpp"

namespace Microsoft { namespace O365 { namespace Security { namespace ETW { namespace Testing {

    /// <summary>
    /// Represents a property that is faked -- one that is built by hand for
    /// the purpose of testing event reaction code.
    /// </summary>
    public ref class SynthRecord {
    internal:

        /// <summary>
        /// Constructs a synthetic property, given a partially filled EventRecord
        /// and a packed sequence of bytes that represent the event's user data.
        /// </summary>
        /// <remarks>
        /// Use a RecordBuilder to get an instance of this.
        /// </remarks>
        SynthRecord(krabs::testing::synth_record *record);

    public:
        /// <summary>
        /// Direct access to the underlying EVENT_RECORD's ProviderId
        /// </summary>
        property Guid ProviderId {
            Guid get() {
                return ConvertGuid(Underlying().EventHeader.ProviderId);
            }

            void set(Guid value) {
                Underlying().EventHeader.ProviderId = ConvertGuid(value);
            }
        }

        /// <summary>
        /// Direct access to the underlying EVENT_RECORD's Id
        /// </summary>
        property uint16_t Id {
            uint16_t get() {
                return Underlying().EventHeader.EventDescriptor.Id;
            }

            void set(uint16_t value) {
                Underlying().EventHeader.EventDescriptor.Id = value;
            }
        }

        /// <summary>
        /// Direct access to the underlying EVENT_RECORD's Version
        /// </summary>
        property uint8_t Version {
            uint8_t get() {
                return Underlying().EventHeader.EventDescriptor.Version;
            }

            void set(uint8_t value) {
                Underlying().EventHeader.EventDescriptor.Version = value;
            }
        }

        /// <summary>
        /// Direct access to the underlying EVENT_RECORD's Opcode
        /// </summary>
        property uint8_t Opcode {
            uint8_t get() {
                return Underlying().EventHeader.EventDescriptor.Opcode;
            }

            void set(uint8_t value) {
                Underlying().EventHeader.EventDescriptor.Opcode = value;
            }
        }

        /// <summary>
        /// Direct access to the underlying EVENT_RECORD's Flags
        /// </summary>
        property uint16_t Flags {
            uint16_t get() {
                return Underlying().EventHeader.Flags;
            }

            void set(uint16_t value) {
                Underlying().EventHeader.Flags = value;
            }
        }

    private:
        /// <summary>
        /// Direct access to the underlying EVENT_RECORD so it can
        /// be tampered with for unit testing.
        /// </summary>
        EVENT_RECORD& Underlying()
        {
            return const_cast<EVENT_RECORD&>(reinterpret_cast<const EVENT_RECORD&>(*record_));
        }

    internal:
        NativePtr<krabs::testing::synth_record> record_;
    };

    // Implementation
    // ------------------------------------------------------------------------

    inline SynthRecord::SynthRecord(krabs::testing::synth_record *record)
    : record_(record)
    { }

} /* namespace Testing */ } /* namespace ETW */ } /* namespace Security */ } /* namespace O365 */ } /* namespace Microsoft */