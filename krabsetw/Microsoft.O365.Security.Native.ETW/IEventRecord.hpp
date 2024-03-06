// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include "Property.hpp"
#include "IEventRecordMetadata.hpp"

using namespace System;
using namespace System::Net;
using namespace System::Runtime::InteropServices;

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// Interface for handling records in C#. Abstracts
    /// using the krabs API to make using krabs more efficient
    /// and to improve testability of code that uses lobsters.
    /// </summary>
    public interface class IEventRecord : IEventRecordMetadata
    {
    public:
        // Schema Methods
        /// <summary>
        /// Returns the name of the event.
        /// </summary>
        property String^ Name { String^ get(); }

        /// <summary>
        /// Retrieves the opcode_name of the event.
        /// </summary>
        property String^ OpcodeName { String^ get(); }

        /// <summary>
        /// Retrieves the task_name of the event.
        /// </summary>
        property String^ TaskName { String^ get(); }

        /// <summary>
        /// Returns the name of the provider that fires this event.
        /// </summary>
        property String^ ProviderName { String^ get(); }

        // Parser Methods

        /// <summary>
        /// Get a unicode string from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the unicode string value associated with the specified property</returns>
        String^ GetUnicodeString(String^ name);

        /// <summary>
        /// Get a unicode string from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the unicode string value associated with the specified property or the specified default value</returns>
        String^ GetUnicodeString(String^ name, String^ defaultValue);

        /// <summary>
        /// Attempt to get a unicode string from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting string</param>
        /// <returns>true if fetching the string succeeded, false otherwise</returns>
        bool TryGetUnicodeString(String^ name, [Out] String^% result);

        /// <summary>
        /// Get a ANSI string from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the ANSI string value associated with the specified property</returns>
        String^ GetAnsiString(String^ name);

        /// <summary>
        /// Get a ANSI string from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the ANSI string value associated with the specified property or the specified default value</returns>
        String^ GetAnsiString(String^ name, String^ defaultValue);

        /// <summary>
        /// Attempt to get a ANSI string from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting string</param>
        /// <returns>true if fetching the string succeeded, false otherwise</returns>
        bool TryGetAnsiString(String^ name, [Out] String^% result);

        /// <summary>
        /// Get a counted string from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the counted string value associated with the specified property</returns>
        String^ GetCountedString(String^ name);

        /// <summary>
        /// Get a counted string from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the counted string value associated with the specified property or the specified default value</returns>
        String^ GetCountedString(String^ name, String^ defaultValue);

        /// <summary>
        /// Attempt to get a counted string from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting string</param>
        /// <returns>true if fetching the string succeeded, false otherwise</returns>
        bool TryGetCountedString(String^ name, [Out] String^% result);

        /// <summary>
        /// Get an IPAddress from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the IPAddress value associated with the specified property</returns>
        IPAddress^ GetIPAddress(String^ name);

        /// <summary>
        /// Get an IPAddress from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the IPAddress value associated with the specified property or the specified default value</returns>
        IPAddress^ GetIPAddress(String^ name, IPAddress^ defaultValue);

        /// <summary>
        /// Attempt to get an IPAddress from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting IPAddress</param>
        /// <returns>true if fetching the IPAddress succeeded, false otherwise</returns>
        bool TryGetIPAddress(String^ name, [Out] IPAddress^% result);

        /// <summary>
        /// Get an SocketAddress from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the SocketAddress value associated with the specified property</returns>
        SocketAddress^ GetSocketAddress(String^ name);

        /// <summary>
        /// Get an SocketAddress from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the SocketAddress value associated with the specified property or the specified default value</returns>
        SocketAddress^ GetSocketAddress(String^ name, SocketAddress^ defaultValue);

        /// <summary>
        /// Attempt to get an SocketAddress from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting SocketAddress</param>
        /// <returns>true if fetching the SocketAddress succeeded, false otherwise</returns>
        bool TryGetSocketAddress(String^ name, [Out] SocketAddress^% result);

        /// <summary>
        /// Get a DateTime from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the DateTime value associated with the specified property</returns>
        DateTime^ GetDateTime(String^ name);

        /// <summary>
        /// Get an DateTime from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the DateTime value associated with the specified property or the specified default value</returns>
        DateTime^ GetDateTime(String^ name, DateTime^ defaultValue);

        /// <summary>
        /// Attempt to get an DateTime from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting DateTime</param>
        /// <returns>true if fetching the DateTime succeeded, false otherwise</returns>
        bool TryGetDateTime(String^ name, [Out] DateTime^% result);

        // Integers

        /// <summary>
        /// Get an Int8 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the Int8 value associated with the specified property</returns>
        int8_t GetInt8(String^ name);

        /// <summary>
        /// Get an Int8 from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the Int8 value associated with the specified property or the specified default value</returns>
        int8_t GetInt8(String^ name, int8_t defaultValue);

        /// <summary>
        /// Attempt to get an Int8 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting Int8</param>
        /// <returns>true if fetching the Int8 succeeded, false otherwise</returns>
        bool TryGetInt8(String^ name, [Out] int8_t% result);

        /// <summary>
        /// Get an UInt8 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the UInt8 value associated with the specified property</returns>
        uint8_t GetUInt8(String^ name);

        /// <summary>
        /// Get an UInt8 from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the UInt8 value associated with the specified property or the specified default value</returns>
        uint8_t GetUInt8(String^ name, uint8_t defaultValue);

        /// <summary>
        /// Attempt to get an UInt8 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting UInt8</param>
        /// <returns>true if fetching the UInt8 succeeded, false otherwise</returns>
        bool  TryGetUInt8(String^ name, [Out] uint8_t% result);

        /// <summary>
        /// Get an Int16 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the Int16 value associated with the specified property</returns>
        int16_t GetInt16(String^ name);

        /// <summary>
        /// Get an Int16 from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the Int16 value associated with the specified property or the specified default value</returns>
        int16_t GetInt16(String^ name, int16_t defaultValue);

        /// <summary>
        /// Attempt to get an Int16 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting Int16</param>
        /// <returns>true if fetching the Int16 succeeded, false otherwise</returns>
        bool TryGetInt16(String^ name, [Out] int16_t% result);

        /// <summary>
        /// Get an UInt16 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the UInt16 value associated with the specified property</returns>
        uint16_t GetUInt16(String^ name);

        /// <summary>
        /// Get an UInt16 from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the UInt16 value associated with the specified property or the specified default value</returns>
        uint16_t GetUInt16(String^ name, uint16_t defaultValue);

        /// <summary>
        /// Attempt to get an UInt16 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting UInt16</param>
        /// <returns>true if fetching the UInt16 succeeded, false otherwise</returns>
        bool  TryGetUInt16(String^ name, [Out] uint16_t% result);

        /// <summary>
        /// Get an Int32 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the Int32 value associated with the specified property</returns>
        int32_t GetInt32(String^ name);

        /// <summary>
        /// Get an Int32 from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the Int32 value associated with the specified property or the specified default value</returns>
        int32_t GetInt32(String^ name, int32_t defaultValue);

        /// <summary>
        /// Attempt to get an Int32 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting Int32</param>
        /// <returns>true if fetching the Int32 succeeded, false otherwise</returns>
        bool TryGetInt32(String^ name, [Out] int32_t% result);

        /// <summary>
        /// Get an UInt32 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the UInt32 value associated with the specified property</returns>
        uint32_t GetUInt32(String^ name);

        /// <summary>
        /// Get an UInt32 from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the UInt32 value associated with the specified property or the specified default value</returns>
        uint32_t GetUInt32(String^ name, uint32_t defaultValue);

        /// <summary>
        /// Attempt to get an UInt32 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting UInt32</param>
        /// <returns>true if fetching the UInt32 succeeded, false otherwise</returns>
        bool  TryGetUInt32(String^ name, [Out] uint32_t% result);

        /// <summary>
        /// Get an Int64 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the Int64 value associated with the specified property</returns>
        int64_t GetInt64(String^ name);

        /// <summary>
        /// Get an Int64 from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the Int64 value associated with the specified property or the specified default value</returns>
        int64_t GetInt64(String^ name, int64_t defaultValue);

        /// <summary>
        /// Attempt to get an Int64 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting Int64</param>
        /// <returns>true if fetching the Int64 succeeded, false otherwise</returns>
        bool TryGetInt64(String^ name, [Out] int64_t% result);

        /// <summary>
        /// Get an UInt64 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the UInt64 value associated with the specified property</returns>
        uint64_t GetUInt64(String^ name);

        /// <summary>
        /// Get an UInt64 from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the UInt64 value associated with the specified property or the specified default value</returns>
        uint64_t GetUInt64(String^ name, uint64_t defaultValue);

        /// <summary>
        /// Attempt to get an UInt64 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting UInt64</param>
        /// <returns>true if fetching the UInt64 succeeded, false otherwise</returns>
        bool  TryGetUInt64(String^ name, [Out] uint64_t% result);

        /// <summary>
        /// Gets an IEnumerable of <see cref="O365::Security::ETW::Property"/>
        /// representing the properties available on the EventRecord.
        /// </summary>
        /// <returns>IEnumerable of Property</returns>
        property IEnumerable<Property^>^ Properties { IEnumerable<Property^>^ get(); }

        /// <summary>
        /// Get a binary field with the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the byte array value associated with the specified property</returns>
        array<Byte>^ GetBinary(String^ name);

        /// <summary>
        /// Attempt to get a binary field with the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting byte array</param>
        /// <returns>true if fetching the data succeeded, false otherwise</returns>
        bool TryGetBinary(String^ name, [Out] array<Byte>^% result);

        /// <summary>
        ///  Retrieves the call stack associated with the record, if enabled.
        /// </summary>
        /// <returns>a list of return addresses</returns>
        List<UIntPtr>^ GetStackTrace();
    };

} } } }