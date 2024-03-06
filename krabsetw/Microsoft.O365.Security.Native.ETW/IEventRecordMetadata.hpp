// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

using namespace System;
using namespace System::Runtime::InteropServices;

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {


    /// <summary>
    /// From the EVENT_HEADER.EventProperty defines:
    /// https://msdn.microsoft.com/en-us/library/windows/desktop/aa363759(v=vs.85).aspx
    /// </summary>
    public enum class EventHeaderProperty : uint16_t
    {
        XML             = 0x0001,
        FORWARDED_XML   = 0x0002,
        LEGACY_EVENTLOG = 0x0004
    };

    /// <summary>
    /// Interface for handling records without access to
    /// the event schema. This can be useful for processing
    /// events that do not have a registered schema.
    /// </summary>
    public interface class IEventRecordMetadata
    {
#pragma region EventDescriptor

        /// <summary>
        /// Returns the ID of this event.
        /// </summary>
        property uint16_t Id { uint16_t get(); }

        /// <summary>
        /// Returns the opcode of this event.
        /// </summary>
        property uint8_t Opcode { uint8_t get(); }

        /// <summary>
        /// Returns the version of this event.
        /// </summary>
        property uint8_t Version { uint8_t get(); }

        /// <summary>
        /// Returns the level of this event.
        /// </summary>
        property uint8_t Level { uint8_t get(); }

#pragma endregion

#pragma region EventHeader

        /// <summary>
        /// Returns the flags of the event.
        /// </summary>
        property uint16_t Flags { uint16_t get(); }

        /// <summary>
        /// Returns the EventProperty of the event.
        /// </summary>
        property EventHeaderProperty EventProperty { EventHeaderProperty get(); }

        /// <summary>
        /// Returns the PID associated with the event.
        /// </summary>
        property unsigned int ProcessId { unsigned int get(); }

        /// <summary>
        /// Returns the Thread ID associated with the event.
        /// </summary>
        property unsigned int ThreadId { unsigned int get(); }

        /// <summary>
        /// Returns the timestamp associated with this event.
        /// </summary>
        property DateTime Timestamp { DateTime get(); }

        /// <summary>
        /// Returns the Thread ID associated with the event.
        /// </summary>
        property Guid ProviderId { Guid get(); }

        /// <summary>
        /// Returns the Activity ID associated with this event.
        /// </summary>
        property Guid ActivityId { Guid get(); }

#pragma endregion

#pragma region EventRecord

        /// <summary>
        /// Returns the size in bytes of the UserData buffer.
        /// </summary>
        /// <returns>the size of the EVENT_RECORD.UserData buffer</returns>
        property uint16_t UserDataLength { uint16_t get(); }

        /// <summary>
        /// Returns a pointer to the UserData buffer.
        /// </summary>
        /// <returns>a pointer to the EVENT_RECORD.UserData buffer</returns>
        property IntPtr UserData { IntPtr get(); }

        /// <summary>
        /// Marshals the event UserData onto the managed heap.
        /// This is expensive. Use the parse methods unless your
        /// event doesn't have a schema.
        /// </summary>
        /// <returns>a byte array representing the marshalled EVENT_RECORD.UserData buffer</returns>
        array<uint8_t>^ CopyUserData();

#pragma endregion

#pragma region ExtendedData

        /// <summary>
        /// If the event's extended data contains a Windows container ID (i.e. event came from inside
        /// a container using process isolation), retrieve it.
        /// Can be expensive, avoid calling more than once per event.
        /// </summary>
        /// <returns>
        /// True if a Guid was present. False if not. If a Guid was present, it will be written into the result 
        /// parameter. Throws a ContainerIdFormatException if the container ID is present but parsing fails.
        /// </returns>
        bool TryGetContainerId([Out] System::Guid% result);

#pragma endregion
    };

} } } }