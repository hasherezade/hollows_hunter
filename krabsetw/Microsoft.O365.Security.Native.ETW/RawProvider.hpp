// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <krabs.hpp>

#include "EventRecord.hpp"
#include "EventRecordMetadata.hpp"
#include "Guid.hpp"
#include "NativePtr.hpp"
#include "Filtering/EventFilter.hpp"

using namespace System;
using namespace System::Runtime::InteropServices;

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// Delegate called when a new ETW <see cref="O365::Security::ETW::EventRecordMetadata"/> is received.
    /// </summary>
    public delegate void IEventRecordMetadataDelegate(
        O365::Security::ETW::IEventRecordMetadata^ record);

    ref class UserTrace;

    /// <summary>
    /// Represents a raw user trace provider and its configuration.
    /// This provider emits IEventRecordMetadata instead of IEventRecord
    /// so it can be used to access events without a registered schema.
    /// </summary>
    /// <seealso cref="O365::Security::ETW::Provider"/>
    public ref class RawProvider {
    public:
        /// <summary>
        /// Specifies a reasonable default to catch all the events with a
        /// bitmask with all bits set.
        /// </summary>
        static const ULONGLONG AllBitsSet = (ULONGLONG)-1;

        /// <summary>
        /// Constructs a RawProvider that is identified by its GUID.
        /// </summary>
        /// <param name="id">the Guid of the provider to enable</param>
        /// <seealso cref="O365::Security::ETW::Provider"/>
        RawProvider(System::Guid id);

        /// <summary>
        /// Constructs a RawProvider that is identified by the provider name.
        /// </summary>
        /// <param name="providerName">the friendly name of the provider to enable</param>
        /// <seealso cref="O365::Security::ETW::Provider"/>
        RawProvider(String^ providerName);

        /// <summary>
        /// Destructs a RawProvider.
        /// </summary>
        ~RawProvider();

        /// <summary>
        /// Represents the "any" value on the provider's options, where
        /// "any" is typically used to request notification if any of the
        /// matching event types fire.
        /// </summary>
        property ULONGLONG Any {
            void set(ULONGLONG value) {
                provider_->any(value);
            }
        }

        /// <summary>
        /// Represents the "all" value on the provider's options, where
        /// "all" is typically used to request notification if all of the
        /// keyword types are matched.
        /// </summary>
        property ULONGLONG All {
            void set(ULONGLONG value) {
                provider_->all(value);
            }
        }

        /// <summary>
        /// Represents the "level" value on the provider's options, where
        /// "level" determines events in what categories are 
        /// enabled for notification.

        /// </summary>
        property UCHAR Level {
            void set(UCHAR value) {
                provider_->level(value);
            }
        }

        /// <summary>
        /// Represents the "EnabledProperty" value on the provider's options.
        /// Values are documented here:
        /// https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters
        /// </summary>
        property TraceFlags TraceFlags {
            ETW::TraceFlags get() {
                return static_cast<ETW::TraceFlags>(provider_->trace_flags());
            }

            void set(O365::Security::ETW::TraceFlags value) {
                provider_->trace_flags((ULONG)value);
            }
        }

        /// <summary>
        /// An event that is invoked when an ETW event is fired in this
        /// provider.
        /// </summary>
        event IEventRecordMetadataDelegate^ OnEvent;

    internal:
        void EventNotification(const EVENT_RECORD &);

    internal:
        delegate void NativeHookDelegate(const EVENT_RECORD &);

        NativeHookDelegate ^del_;
        NativePtr<krabs::provider<>> provider_;
        GCHandle delegateHookHandle_;
        GCHandle delegateHandle_;
        void SetUpProvider();
    };

    // Implementation
    // ------------------------------------------------------------------------

    inline RawProvider::RawProvider(System::Guid id)
        : provider_(ConvertGuid(id))
    {
        SetUpProvider();
    }

    inline RawProvider::RawProvider(String^ providerName)
        : provider_(msclr::interop::marshal_as<std::wstring>(providerName))
    {
        SetUpProvider();
    }

    inline void RawProvider::SetUpProvider()
    {
        del_ = gcnew NativeHookDelegate(this, &RawProvider::EventNotification);
        delegateHandle_ = GCHandle::Alloc(del_);
        auto bridged = Marshal::GetFunctionPointerForDelegate(del_);
        delegateHookHandle_ = GCHandle::Alloc(bridged);

        provider_->add_on_event_callback((krabs::c_provider_callback)bridged.ToPointer());
    }

    inline RawProvider::~RawProvider()
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

    inline void RawProvider::EventNotification(const EVENT_RECORD &record)
    {
        OnEvent(gcnew EventRecordMetadata(record));
    }
} } } }