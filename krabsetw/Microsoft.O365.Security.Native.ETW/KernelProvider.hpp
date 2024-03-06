// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <krabs.hpp>
#include <krabs/perfinfo_groupmask.hpp>

#include "EventRecord.hpp"
#include "EventRecordMetadata.hpp"
#include "Guid.hpp"
#include "NativePtr.hpp"
#include "Filtering/EventFilter.hpp"

using namespace System;
using namespace System::Runtime::InteropServices;

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// Represents a kernel trace provider and its configuration.
    /// </summary>
    public ref class KernelProvider {
    public:

        /// <summary>
        /// Constructs a KernelProvider that is identified by its GUID.
        /// </summary>
        /// <param name="flags">the trace flags to set</param>
        /// <param name="id">the guid of the kernel trace</param>
        /// <remarks>
        /// More information about trace flags can be found on MSDN:
        /// <see href="https://msdn.microsoft.com/en-us/library/windows/desktop/aa363784(v=vs.85).aspx"/>
        /// </remarks>
        KernelProvider(unsigned int flags, System::Guid id);

        /// <summary>
        /// Constructs a KernelProvider that is identified by its GUID.
        /// </summary>
        /// <param name="id">the guid of the kernel trace</param>
        /// <param name="mask">the group mask to set</param>
        /// <remarks>
        /// Only supported on Windows 8 and newer.
        /// More information about group masks can be found here:
        /// <see href="https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/tracesup/perfinfo_groupmask.htm"/>
        /// </remarks>
        KernelProvider(System::Guid id, PERFINFO_MASK mask);

        /// <summary>
        /// Destructs a KernelProvider.
        /// </summary>
        ~KernelProvider();

        /// <summary>
        /// Adds a new EventFilter to the provider.
        /// </summary>
        /// <param name="filter">
        /// the <see cref="O365::Security::ETW::EventFilter"/> to
        /// filter incoming events with
        /// </param>
        void AddFilter(O365::Security::ETW::EventFilter ^filter) {
            provider_->add_filter(filter);
        }

        /// <summary>
        /// An event that is invoked when an ETW event is fired in this
        /// provider.
        /// </summary>
        event IEventRecordDelegate^ OnEvent;

        /// <summary>
        /// An event that is invoked when an ETW event is received
        /// but an error occurs handling the record.
        /// </summary>
        event EventRecordErrorDelegate^ OnError;

        /// <summary>
        /// Retrieves the GUID associated with this provider
        /// </summary>
        /// <returns>returns the GUID associated with this provider object</returns>
        property Guid Id {
            Guid get() {
                GUID guid = provider_->id();
                return Guid(guid.Data1, guid.Data2, guid.Data3,
                            guid.Data4[0], guid.Data4[1],
                            guid.Data4[2], guid.Data4[3],
                            guid.Data4[4], guid.Data4[5],
                            guid.Data4[6], guid.Data4[7]);
            }
        }


    internal:
        void EventNotification(const EVENT_RECORD &, const krabs::trace_context &);

    internal:
        delegate void NativeHookDelegate(const EVENT_RECORD &, const krabs::trace_context &);

        NativeHookDelegate ^del_;
        NativePtr<krabs::kernel_provider> provider_;
        GCHandle delegateHookHandle_;
        GCHandle delegateHandle_;
    };

    // Implementation
    // ------------------------------------------------------------------------

    inline KernelProvider::KernelProvider(unsigned int flags, System::Guid id)
    : provider_(flags, ConvertGuid(id))
    {
        del_ = gcnew NativeHookDelegate(this, &KernelProvider::EventNotification);
        delegateHandle_ = GCHandle::Alloc(del_);
        auto bridged = Marshal::GetFunctionPointerForDelegate(del_);
        delegateHookHandle_ = GCHandle::Alloc(bridged);

        provider_->add_on_event_callback((krabs::c_provider_callback)bridged.ToPointer());
    }

    inline KernelProvider::KernelProvider(System::Guid id, PERFINFO_MASK mask)
        : provider_(ConvertGuid(id), mask)
    {
        del_ = gcnew NativeHookDelegate(this, &KernelProvider::EventNotification);
        delegateHandle_ = GCHandle::Alloc(del_);
        auto bridged = Marshal::GetFunctionPointerForDelegate(del_);
        delegateHookHandle_ = GCHandle::Alloc(bridged);

        provider_->add_on_event_callback((krabs::c_provider_callback)bridged.ToPointer());
    }

    inline KernelProvider::~KernelProvider()
    {
        if (delegateHandle_.IsAllocated)
        {
            delegateHandle_.Free();
        }

        if (delegateHookHandle_.IsAllocated)
        {
            delegateHookHandle_.Free();
        }
    }

    inline void KernelProvider::EventNotification(const EVENT_RECORD &record, const krabs::trace_context &trace_context)
    {
        try
        {
            krabs::schema schema(record, trace_context.schema_locator);
            krabs::parser parser(schema);

            OnEvent(gcnew EventRecord(record, schema, parser));
        }
        catch (const krabs::could_not_find_schema& ex)
        {
            auto msg = gcnew String(ex.what());
            auto metadata = gcnew EventRecordMetadata(record);

            OnError(gcnew EventRecordError(msg, metadata));
        }
    }

} } } }