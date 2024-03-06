// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <krabs.hpp>

#include "../Guid.hpp"
#include "../NativePtr.hpp"
#include "SynthRecord.hpp"

namespace Microsoft { namespace O365 { namespace Security { namespace ETW { namespace Testing {

    /// <summary>
    /// Enables creation of synthetic events in order to test client code.
    /// </summary>
    /// <remarks>
    //    This beast of a class enables the creation of EVENT_RECORD events
    //    for testing. The class accepts a collection of keyed pairs that are
    //    then packed into the event according to the schema on the local
    //    machine. Because a lot of this is Dark Arts kind of stuff, there
    //    really isn't a guarantee that this code works perfectly. Please
    //    file bugs.
    /// </remarks>
    public ref class RecordBuilder {
    public:
        RecordBuilder(System::Guid guid, int id, int version, int opcode);
        RecordBuilder(System::Guid guid, int id, int version);

        /// <summary>
        /// Packs the event properties into an EVENT_RECORD
        /// </summary>
        SynthRecord^ Pack();

        /// <summary>
        /// Packs the event properties into an EVENT_RECORD, but doesn't throw
        /// when the properties are not completely filled (i.g., when not all
        /// properties are supplied)
        /// </summary>
        SynthRecord^ PackIncomplete();

        /// <summary>
        /// Provides access to the EventHeader that will be packed into the
        /// faked record.
        /// </summary>
        property EventHeader^ Header {
            EventHeader^ get() {
                return gcnew EventHeader(&builder_->header());
            }
        }

        /// <summary>
        /// Adds a property with an ANSI string to the record.
        /// </summary>
        void AddAnsiString(System::String^ name, System::String^ value);

        /// <summary>
        /// Adds a property with a unicode string to the record.
        /// </summary>
        void AddUnicodeString(System::String^ name, System::String^ value);

        generic <typename T>
        void AddValue(System::String^ name, T value);

        /// <summary>
        /// Adds a container ID extended data item
        /// </summary>
        void AddContainerId(System::Guid container_id);

    internal:
        NativePtr<krabs::testing::record_builder> builder_;

        template <typename T>
        void AddValueInternal(System::String^ name, T value);
    };


    // Implementation
    // ------------------------------------------------------------------------

    inline RecordBuilder::RecordBuilder(System::Guid guid, int id, int version, int opcode)
    : builder_(ConvertGuid(guid), id, version, opcode)
    {
    }

    inline RecordBuilder::RecordBuilder(System::Guid guid, int id, int version)
    : RecordBuilder(guid, id, version, 0)
    {
    }

    inline SynthRecord^ RecordBuilder::Pack()
    {
        try
        {
            // SynthRecord owns the memory management of nativeRecord
            auto nativeRecord  = new krabs::testing::synth_record(builder_->pack());
            SynthRecord^ managed = gcnew SynthRecord(nativeRecord);
            return managed;
        }
        catch (const krabs::could_not_find_schema& ex)
        {
            auto msg = gcnew String(ex.what());
            throw gcnew CouldNotFindSchema(msg);
        }
        catch (const std::invalid_argument& ex)
        {
            auto msg = gcnew String(ex.what());
            throw gcnew ArgumentException(msg);
        }
        catch (const std::domain_error& ex)
        {
            auto msg = gcnew String(ex.what());
            throw gcnew ArgumentException(msg);
        }
    }

    inline SynthRecord^ RecordBuilder::PackIncomplete()
    {
        try
        {
            // SynthRecord owns the memory management of nativeRecord
            auto nativeRecord = new krabs::testing::synth_record(builder_->pack_incomplete());
            SynthRecord^ managed = gcnew SynthRecord(nativeRecord);
            return managed;
        }
        catch (const krabs::could_not_find_schema& ex)
        {
            auto msg = gcnew String(ex.what());
            throw gcnew CouldNotFindSchema(msg);
        }
        catch (const std::invalid_argument& ex)
        {
            auto msg = gcnew String(ex.what());
            throw gcnew ArgumentException(msg);
        }
    }

    inline void RecordBuilder::AddAnsiString(System::String^ name, System::String^ value)
    {
        AddValueInternal(name, msclr::interop::marshal_as<std::string>(value));
    }

    inline void RecordBuilder::AddUnicodeString(System::String^ name, System::String^ value)
    {
        AddValueInternal(name, msclr::interop::marshal_as<std::wstring>(value));
    }

    generic <typename T>
    inline void RecordBuilder::AddValue(System::String^ name, T value)
    {
        if (T::typeid == Int16::typeid)
            AddValueInternal(name, (Int16)value);

        else if (T::typeid == UInt16::typeid)
            AddValueInternal(name, (UInt16)value);

        else if (T::typeid == Int32::typeid)
            AddValueInternal(name, (Int32)value);

        else if (T::typeid == UInt32::typeid)
            AddValueInternal(name, (UInt32)value);

        else if (T::typeid == Int64::typeid)
            AddValueInternal(name, (Int64)value);

        else if (T::typeid == UInt64::typeid)
            AddValueInternal(name, (UInt64)value);

        else
        {
            auto msg = System::String::Format("Add value does not support type {0}", T::typeid);
            throw gcnew ArgumentException(msg);
        }
    }

    template <typename T>
    void RecordBuilder::AddValueInternal(System::String^ name, T value)
    {
        auto propName = msclr::interop::marshal_as<std::wstring>(name);
        builder_->add_properties()(propName, value);
    }

    inline void RecordBuilder::AddContainerId(System::Guid container_id)
    {
        builder_->add_container_id_extended_data(ConvertGuid(container_id));
    }

} /* namespace Testing */ } /* namespace ETW */ } /* namespace Security */ } /* namespace O365 */ } /* namespace Microsoft */