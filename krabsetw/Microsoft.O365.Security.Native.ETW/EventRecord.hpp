// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <krabs.hpp>
#include "Errors.hpp"
#include "EventRecordMetadata.hpp"
#include "IEventRecord.hpp"
#include "Property.hpp"

#include <msclr\marshal.h>
#include <msclr\marshal_cppstd.h>

using namespace System;
using namespace System::Net;
using namespace System::Runtime::InteropServices;
using namespace System::Security::Principal;

using namespace msclr::interop;

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// EventRecord represents a managed instance of an event from ETW.
    /// </summary>
    public ref class EventRecord : public EventRecordMetadata, public IEventRecord
    {
    private:
        const krabs::schema* schema_;
        krabs::parser* parser_;

    internal:

        EventRecord(
            const EVENT_RECORD& record,
            const krabs::schema& schema,
            krabs::parser& parser)
            : EventRecordMetadata(record)
            , schema_(&schema)
            , parser_(&parser) { }

    public:

#pragma region Schema
        /// <summary>
        /// Retrieves the name of the event.
        /// </summary>
        virtual property String^ Name
        {
            String^ get() { return gcnew String(schema_->event_name()); }
        }

        /// <summary>
        /// Retrieves the opcode_name of the event.
        /// </summary>
        virtual property String^ OpcodeName
        {
            String^ get() { return gcnew String(schema_->opcode_name()); }
        }

        /// <summary>
        /// Retrieves the task_name of the event.
        /// </summary>
        virtual property String^ TaskName
        {
            String^ get() { return gcnew String(schema_->task_name()); }
        }

        /// <summary>
        /// Retrieves the name of the provider that fires this event.
        /// </summary>
        virtual property String^ ProviderName
        {
            String^ get() { return gcnew String(schema_->provider_name()); }
        }

#pragma endregion

#pragma region Parser

#pragma region Unicode String
        /// <summary>
        /// Get a unicode string from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the unicode string value associated with the specified property</returns>
        virtual String^ GetUnicodeString(String^ name)
        {
            const auto& str = GetValue<std::wstring>(name);
            return gcnew String(str.c_str());
        }

        /// <summary>
        /// Get a unicode string from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the unicode string value associated with the specified property or the specified default value</returns>
        virtual String^ GetUnicodeString(String^ name, String^ defaultValue)
        {
            String^ str;

            if (TryGetUnicodeString(name, str))
                return str;

            return defaultValue;
        }

        /// <summary>
        /// Attempt to get a unicode string from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting string</param>
        /// <returns>true if fetching the string succeeded, false otherwise</returns>
        virtual bool TryGetUnicodeString(String^ name, [Out] String^% result)
        {
            std::wstring str;
            bool success = TryGetValue(name, str);

            if (success)
                result = gcnew String(str.c_str());

            return success;
        }

#pragma endregion

#pragma region Ansi String

        /// <summary>
        /// Get a ANSI string from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the ANSI string value associated with the specified property</returns>
        virtual String^ GetAnsiString(String^ name)
        {
            const auto& str = GetValue<std::string>(name);
            return gcnew String(str.c_str());
        }

        /// <summary>
        /// Get a ANSI string from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the ANSI string value associated with the specified property or the specified default value</returns>
        virtual String^ GetAnsiString(String^ name, String^ defaultValue)
        {
            String^ str;

            if (TryGetAnsiString(name, str))
                return str;

            return defaultValue;
        }

        /// <summary>
        /// Attempt to get a ANSI string from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting string</param>
        /// <returns>true if fetching the string succeeded, false otherwise</returns>
        virtual bool TryGetAnsiString(String^ name, [Out] String^% result)
        {
            std::string str;
            bool success = TryGetValue(name, str);

            if (success)
                result = gcnew String(str.c_str());

            return success;
        }

#pragma endregion

#pragma region Counted String
        /// <summary>
        /// Get a counted string from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the counted string value associated with the specified property</returns>
        virtual String^ GetCountedString(String^ name)
        {
            const auto& str = GetValue<const krabs::counted_string*>(name);
            return ConvertToString(*str);
        }

        /// <summary>
        /// Get a counted string from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the counted string value associated with the specified property or the specified default value</returns>
        virtual String^ GetCountedString(String^ name, String^ defaultValue)
        {
            String^ str;

            if (TryGetCountedString(name, str))
                return str;

            return defaultValue;
        }

        /// <summary>
        /// Attempt to get a counted string from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting string</param>
        /// <returns>true if fetching the string succeeded, false otherwise</returns>
        virtual bool TryGetCountedString(String^ name, [Out] String^% result)
        {
            const krabs::counted_string* str;
            bool success = TryGetValue(name, str);

            if (success)
                result = ConvertToString(*str);

            return success;
        }

#pragma endregion

#pragma region IPAddress

        /// <summary>
        /// Get an IPAddress from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the IPAddress value associated with the specified property</returns>
        virtual IPAddress^ GetIPAddress(String^ name)
        {
            const auto& addr = GetValue<krabs::ip_address>(name);
            return ConvertToIPAddress(addr);
        }

        /// <summary>
        /// Get an IPAddress from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the IPAddress value associated with the specified property or the specified default value</returns>
        virtual IPAddress^ GetIPAddress(String^ name, IPAddress^ defaultValue)
        {
            IPAddress^ addr;

            if (TryGetIPAddress(name, addr))
                return addr;

            return defaultValue;
        }

        /// <summary>
        /// Attempt to get an IPAddress from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting IPAddress</param>
        /// <returns>true if fetching the IPAddress succeeded, false otherwise</returns>
        virtual bool TryGetIPAddress(String^ name, [Out] IPAddress^% result)
        {
            krabs::ip_address addr;
            bool success = TryGetValue(name, addr);

            if (success)
                result = ConvertToIPAddress(addr);

            return success;
        }

#pragma endregion

#pragma region Socket Address
        /// <summary>
        /// Get an SocketAddress from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the SocketAddress value associated with the specified property</returns>
        virtual SocketAddress^ GetSocketAddress(String^ name)
        {
            const auto& addr = GetValue<krabs::socket_address>(name);
            return ConvertToSocketAddress(addr);
        }

        /// <summary>
        /// Get an SocketAddress from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the SocketAddress value associated with the specified property or the specified default value</returns>
        virtual SocketAddress^ GetSocketAddress(String^ name, SocketAddress^ defaultValue)
        {
            SocketAddress^ addr;

            if (TryGetSocketAddress(name, addr))
                return addr;

            return defaultValue;
        }

        /// <summary>
        /// Attempt to get an SocketAddress from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting SocketAddress</param>
        /// <returns>true if fetching the SocketAddress succeeded, false otherwise</returns>
        virtual bool TryGetSocketAddress(String^ name, [Out] SocketAddress^% result)
        {
            krabs::socket_address addr;
            bool success = TryGetValue(name, addr);

            if (success)
                result = ConvertToSocketAddress(addr);

            return success;
        }
#pragma endregion

#pragma region Security Identifier
        /// <summary>
        /// Get a Security Identifier (SID) from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the SID value associated with the specified property</returns>
        virtual SecurityIdentifier^ GetSecurityIdentifier(String^ name)
        {
            const auto& addr = GetValue<krabs::sid>(name);
            return ConvertToSecurityIdentifier(addr);
        }

        /// <summary>
        /// Get a Security Identifier (SID) from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the SocketAddress value associated with the specified property or the specified default value</returns>
        virtual SecurityIdentifier^ GetSecurityIdentifier(String^ name, SecurityIdentifier^ defaultValue)
        {
            SecurityIdentifier^ addr;

            if (TryGetSecurityIdentifier(name, addr))
                return addr;

            return defaultValue;
        }

        /// <summary>
        /// Attempt to get a Security Identifier (SID) from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting SocketAddress</param>
        /// <returns>true if fetching the SocketAddress succeeded, false otherwise</returns>
        virtual bool TryGetSecurityIdentifier(String^ name, [Out] SecurityIdentifier^% result)
        {
            krabs::sid addr;
            bool success = TryGetValue(name, addr);

            if (success)
                result = ConvertToSecurityIdentifier(addr);

            return success;
        }
#pragma endregion

#pragma region Pointer
        /// <summary>
        /// Get a Pointer type from the from the specified property name
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>The IntPtr associated with the specified property</returns>
        virtual IntPtr^ GetPointer(String^ name)
        {
            const auto& addr = GetValue<krabs::pointer>(name);
            return ConvertToPointer(addr);
        }

        /// <summary>
        /// Get a Pointer from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the IntPtr value associated with the specified property or the specified default value</returns>
        virtual IntPtr^ GetPointer(String^ name, IntPtr^ defaultValue)
        {
            IntPtr^ addr;

            if (TryGetPointer(name, addr))
                return addr;

            return defaultValue;
        }

        /// <summary>
        /// Attempt to get a Pointer from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting IntPtr</param>
        /// <returns>true if fetching the IntPtr succeeded, false otherwise</returns>
        virtual bool TryGetPointer(String^ name, [Out] IntPtr^% result)
        {
            krabs::pointer addr;
            bool success = TryGetValue(name, addr);

            if (success)
                result = ConvertToPointer(addr);

            return success;
        }
#pragma endregion

#pragma region DateTime
        /// <summary>
        /// Get a DateTime from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the DateTime value associated with the specified property</returns>
        virtual DateTime^ GetDateTime(String^ name)
        {
            const auto& time = GetValue<::FILETIME>(name);
            LARGE_INTEGER *largeInt = (LARGE_INTEGER*)&time;
            return DateTime::FromFileTimeUtc(largeInt->QuadPart);
        }

        /// <summary>
        /// Get an DateTime from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the DateTime value associated with the specified property or the specified default value</returns>
        virtual DateTime^ GetDateTime(String^ name, DateTime^ defaultValue)
        {
            DateTime^ time;

            if (TryGetDateTime(name, time))
                return time;

            return defaultValue;
        }

        /// <summary>
        /// Attempt to get an DateTime from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting DateTime</param>
        /// <returns>true if fetching the DateTime succeeded, false otherwise</returns>
        virtual bool TryGetDateTime(String^ name, [Out] DateTime^% result)
        {
            ::FILETIME time;
            bool success = TryGetValue(name, time);
            LARGE_INTEGER *largeInt = (LARGE_INTEGER*)&time;

            if (success)
                result = DateTime::FromFileTimeUtc(largeInt->QuadPart);

            return success;
        }
#pragma endregion

#pragma region Integers

        /// <summary>
        /// Get an Int8 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the Int8 value associated with the specified property</returns>
        virtual int8_t GetInt8(String^ name)
        {
            return GetValue<int8_t>(name);
        }

        /// <summary>
        /// Get an Int8 from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the Int8 value associated with the specified property or the specified default value</returns>
        virtual int8_t GetInt8(String^ name, int8_t defaultValue)
        {
            return GetValueOrDefault(name, defaultValue);
        }

        /// <summary>
        /// Attempt to get an Int8 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting Int8</param>
        /// <returns>true if fetching the Int8 succeeded, false otherwise</returns>
        virtual bool TryGetInt8(String^ name, [Out] int8_t% result)
        {
            return TryGetValue(name, result);
        }

        /// <summary>
        /// Get an UInt8 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the UInt8 value associated with the specified property</returns>
        virtual uint8_t GetUInt8(String^ name)
        {
            return GetValue<uint8_t>(name);
        }

        /// <summary>
        /// Get an UInt8 from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the UInt8 value associated with the specified property or the specified default value</returns>
        virtual uint8_t GetUInt8(String^ name, uint8_t defaultValue)
        {
            return GetValueOrDefault(name, defaultValue);
        }

        /// <summary>
        /// Attempt to get an UInt8 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting UInt8</param>
        /// <returns>true if fetching the UInt8 succeeded, false otherwise</returns>
        virtual bool TryGetUInt8(String^ name, [Out] uint8_t% result)
        {
            return TryGetValue(name, result);
        }

        /// <summary>
        /// Get an Int16 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the Int16 value associated with the specified property</returns>
        virtual int16_t GetInt16(String^ name)
        {
            return GetValue<int16_t>(name);
        }

        /// <summary>
        /// Get an Int16 from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the Int16 value associated with the specified property or the specified default value</returns>
        virtual int16_t GetInt16(String^ name, int16_t defaultValue)
        {
            return GetValueOrDefault(name, defaultValue);
        }

        /// <summary>
        /// Attempt to get an Int16 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting Int16</param>
        /// <returns>true if fetching the Int16 succeeded, false otherwise</returns>
        virtual bool TryGetInt16(String^ name, [Out] int16_t% result)
        {
            return TryGetValue(name, result);
        }

        /// <summary>
        /// Get an UInt16 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the UInt16 value associated with the specified property</returns>
        virtual uint16_t GetUInt16(String^ name)
        {
            return GetValue<uint16_t>(name);
        }

        /// <summary>
        /// Get an UInt16 from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the UInt16 value associated with the specified property or the specified default value</returns>
        virtual uint16_t GetUInt16(String^ name, uint16_t defaultValue)
        {
            return GetValueOrDefault(name, defaultValue);
        }

        /// <summary>
        /// Attempt to get an UInt16 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting UInt16</param>
        /// <returns>true if fetching the UInt16 succeeded, false otherwise</returns>
        virtual bool TryGetUInt16(String^ name, [Out] uint16_t% result)
        {
            return TryGetValue(name, result);
        }

        /// <summary>
        /// Get an Int32 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the Int32 value associated with the specified property</returns>
        virtual int32_t GetInt32(String^ name)
        {
            return GetValue<int32_t>(name);
        }

        /// <summary>
        /// Get an Int32 from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the Int32 value associated with the specified property or the specified default value</returns>
        virtual int32_t GetInt32(String^ name, int32_t defaultValue)
        {
            return GetValueOrDefault(name, defaultValue);
        }

        /// <summary>
        /// Attempt to get an Int32 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting Int32</param>
        /// <returns>true if fetching the Int32 succeeded, false otherwise</returns>
        virtual bool TryGetInt32(String^ name, [Out] int32_t% result)
        {
            return TryGetValue(name, result);
        }

        /// <summary>
        /// Get an UInt32 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the UInt32 value associated with the specified property</returns>
        virtual uint32_t GetUInt32(String^ name)
        {
            return GetValue<uint32_t>(name);
        }

        /// <summary>
        /// Get an UInt32 from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the UInt32 value associated with the specified property or the specified default value</returns>
        virtual uint32_t GetUInt32(String^ name, uint32_t defaultValue)
        {
            return GetValueOrDefault(name, defaultValue);
        }

        /// <summary>
        /// Attempt to get an UInt32 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting UInt32</param>
        /// <returns>true if fetching the UInt32 succeeded, false otherwise</returns>
        virtual bool TryGetUInt32(String^ name, [Out] uint32_t% result)
        {
            return TryGetValue(name, result);
        }

        /// <summary>
        /// Get an Int64 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the Int64 value associated with the specified property</returns>
        virtual int64_t GetInt64(String^ name)
        {
            return GetValue<int64_t>(name);
        }

        /// <summary>
        /// Get an Int64 from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the Int64 value associated with the specified property or the specified default value</returns>
        virtual int64_t GetInt64(String^ name, int64_t defaultValue)
        {
            return GetValueOrDefault(name, defaultValue);
        }

        /// <summary>
        /// Attempt to get an Int64 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting Int64</param>
        /// <returns>true if fetching the Int64 succeeded, false otherwise</returns>
        virtual bool TryGetInt64(String^ name, [Out] int64_t% result)
        {
            return TryGetValue(name, result);
        }

        /// <summary>
        /// Get an UInt64 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the UInt64 value associated with the specified property</returns>
        virtual uint64_t GetUInt64(String^ name)
        {
            return GetValue<uint64_t>(name);
        }

        /// <summary>
        /// Get an UInt64 from the specified property name or returns
        /// the specified default value.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="defaultValue">the default value to return if the property lookup fails</param>
        /// <returns>the UInt64 value associated with the specified property or the specified default value</returns>
        virtual uint64_t GetUInt64(String^ name, uint64_t defaultValue)
        {
            return GetValueOrDefault(name, defaultValue);
        }

        /// <summary>
        /// Attempt to get an UInt64 from the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting UInt64</param>
        /// <returns>true if fetching the UInt64 succeeded, false otherwise</returns>
        virtual bool TryGetUInt64(String^ name, [Out] uint64_t% result)
        {
            return TryGetValue(name, result);
        }

#pragma endregion

        /// <summary>
        /// Gets an IEnumerable of <see cref="O365::Security::ETW::Property"/>
        /// representing the properties available on the EventRecord.
        /// </summary>
        /// <returns>IEnumerable of Property</returns>
        virtual property IEnumerable<Property^>^ Properties
        {
            IEnumerable<Property^>^ get() { return gcnew PropertyEnumerable(*schema_); }
        }

        /// <summary>
        /// Get a binary field with the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <returns>the byte array value associated with the specified property</returns>
        virtual array<Byte>^ GetBinary(String^ name)
        {
            auto data = GetValue<krabs::binary>(name);

            return ConvertToByteArray(data);
        }

        /// <summary>
        /// Attempt to get a binary field with the specified property name.
        /// </summary>
        /// <param name="name">property name</param>
        /// <param name="result">the resulting byte array</param>
        /// <returns>true if fetching the data succeeded, false otherwise</returns>
        virtual bool TryGetBinary(String^ name, [Out] array<Byte>^% result)
        {
            krabs::binary data;
            bool success = TryGetValue(name, data);

            if (success)
                result = ConvertToByteArray(data);

            return success;
        }

        /// <summary>
        /// Retrieves the call stack associated with the record, if enabled.
        /// </summary>
        /// <returns>a list of return addresses</returns>
        virtual List<UIntPtr>^ GetStackTrace()
        {
            auto stackTrace = gcnew List<UIntPtr>();
            for (auto& returnAddress : schema_->stack_trace())
            {
                stackTrace->Add(UIntPtr(returnAddress));
            }
            return stackTrace;
        }

#pragma endregion

    private:
        template <typename T>
        T GetValue(String^ name)
        {
            std::wstring propName = marshal_as<std::wstring>(name);

            try
            {
                return parser_->parse<T>(propName);
            }
            catch (const krabs::type_mismatch_assert& ex)
            {
                // This can only happen in debug builds, we need
                // to wrap the C++ exception for C#

                auto msg = gcnew String(ex.what());
                throw gcnew TypeMismatchAssert(msg);
            }
            catch (const std::exception& ex)
            {
                auto msg = gcnew String(ex.what());
                throw gcnew ParserException(msg);
            }
        }

        template <typename T>
        T GetValueOrDefault(String^ name, T defaultValue)
        {
            T result;
            bool success = TryGetValue(name, result);

            if (success) return result;

            return defaultValue;
        }

        template <typename T>
        bool TryGetValue(String^ name, T% result)
        {
            try
            {
                T value;

                std::wstring propName = marshal_as<std::wstring>(name);
                bool success = parser_->try_parse(propName, value);

                if (success) result = value;

                return success;
            }
            catch (const krabs::type_mismatch_assert& ex)
            {
                // This can only happen in debug builds, we need
                // to wrap the C++ exception for C#

                auto msg = gcnew String(ex.what());
                throw gcnew TypeMismatchAssert(msg);
            }
        }

        IPAddress^ ConvertToIPAddress(const krabs::ip_address& addr)
        {
            int size = addr.is_ipv6 ? 16 : 4;
            array<Byte>^ bytes = gcnew array<Byte>(size);
            Marshal::Copy(IntPtr((void*)&addr), bytes, 0, size);

            return gcnew IPAddress(bytes);
        }

        SocketAddress^ ConvertToSocketAddress(const krabs::socket_address& addr)
        {
            auto managed = gcnew SocketAddress((Sockets::AddressFamily)addr.sa_stor.ss_family);
            BYTE* ptr = (BYTE*)&(addr.sa_stor);

            int size = addr.sa_stor.ss_family == AF_INET ? sizeof addr.sa_in : sizeof addr.sa_in6;

            for (int ii = 0; ii < size; ii++)
                managed[ii] = ptr[ii];

            return managed;
        }

        SecurityIdentifier^ ConvertToSecurityIdentifier(const krabs::sid& addr)
        {
            auto managed_string = gcnew String(addr.sid_string.c_str());
            auto managed = gcnew SecurityIdentifier(managed_string);
            return managed;
        }

        IntPtr^ ConvertToPointer(const krabs::pointer& addr)
        {
            auto managed = gcnew IntPtr(static_cast<long long>(addr.address));
            return managed;
        }

        String^ ConvertToString(const krabs::counted_string& value)
        {
            return Marshal::PtrToStringUni(
                IntPtr(reinterpret_cast<long long>(value.string())),
                (int)value.length());
        }

        array<Byte>^ ConvertToByteArray(const krabs::binary& data)
        {
            auto managed = gcnew array<Byte>((int)data.bytes().size());
            IntPtr start((void*)&data.bytes()[0]);

            if (start == IntPtr::Zero) return nullptr;

            Marshal::Copy(start, managed, 0, (int)data.bytes().size());

            return managed;
        }
    };

} } } }