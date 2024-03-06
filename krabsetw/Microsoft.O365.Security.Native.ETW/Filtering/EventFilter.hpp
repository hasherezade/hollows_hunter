// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <krabs.hpp>

#include "../Conversions.hpp"
#include "../EventRecordError.hpp"
#include "../EventRecord.hpp"
#include "../EventRecordMetadata.hpp"
#include "../Guid.hpp"
#include "../IEventRecord.hpp"
#include "../IEventRecordError.hpp"
#include "../NativePtr.hpp"
#include "Predicate.hpp"

using namespace System;
using namespace System::Runtime::InteropServices;

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// Delegate called when a new ETW <see cref="O365::Security::ETW::EventRecord"/> is received.
    /// </summary>
    public delegate void IEventRecordDelegate(O365::Security::ETW::IEventRecord^ record);

    /// <summary>
    /// Delegate called on errors when processing an <see cref="O365::Security::ETW::EventRecord"/>.
    /// </summary>
    public delegate void EventRecordErrorDelegate(O365::Security::ETW::IEventRecordError^ error);

    /// <summary>
    /// Allows for filtering an event in the native layer before it bubbles
    /// up to callbacks.
    /// </summary>
    public ref class EventFilter {
    public:

        /// <summary>
        /// Constructs an EventFilter with the given Predicate.
        /// </summary>
        /// <param name="predicate">the predicate to use to filter an event</param>
        EventFilter(O365::Security::ETW::Predicate ^predicate);

        /// <summary>
        /// Constructs an EventFilter with the given event ID.
        /// </summary>
        /// <param name="eventId">the event ID to filter using provider-based filtering</param>
        EventFilter(unsigned short eventId);

        /// <summary>
        /// Constructs an EventFilter with the given event ID and Predicate.
        /// </summary>
        /// <param name="eventId">the event ID to filter using provider-based filtering</param>
        /// <param name="predicate">the predicate to use to filter an event</param>
        EventFilter(unsigned short eventId, O365::Security::ETW::Predicate^ predicate);

        /// <summary>
        /// Constructs an EventFilter with the given event IDs.
        /// </summary>
        /// <param name="eventIds">the event IDs to filter using provider-based filtering</param>
        EventFilter(List<unsigned short>^ eventIds);

        /// <summary>
        /// Constructs an EventFilter with the given event IDs and Predicate.
        /// </summary>
        /// <param name="eventIds">the event IDs to filter using provider-based filtering</param>
        /// <param name="predicate">the predicate to use to filter an event</param>
        EventFilter(List<unsigned short>^ eventIds, O365::Security::ETW::Predicate^ predicate);

        /// <summary>
        /// Destructs an EventFilter.
        /// </summary>
        ~EventFilter();

        /// <summary>
        /// An event that is invoked when an ETW event is fired on this
        /// filter and the event meets the given predicate.
        /// </summary>
        event IEventRecordDelegate^ OnEvent;

        /// <summary>
        /// An event that is invoked when an ETW event is received
        /// but an error occurs handling the record.
        /// </summary>
        event EventRecordErrorDelegate^ OnError;


    internal:
        /// <summary>
        /// Allows implicit conversion to a krabs::event_filter.
        /// </summary>
        /// <returns>the native representation of an EventFilter</returns>
        operator krabs::event_filter&()
        {
            return *filter_;
        }

        void EventNotification(const EVENT_RECORD &, const krabs::trace_context &);
        void ErrorNotification(const EVENT_RECORD&, const std::string&);

    internal:
        delegate void EventReceivedNativeHookDelegate(const EVENT_RECORD &, const krabs::trace_context &);
        delegate void ErrorReceivedNativeHookDelegate(const EVENT_RECORD &, const std::string &);

        NativePtr<krabs::event_filter> filter_;
        EventReceivedNativeHookDelegate^ eventReceivedDelegate_;
        ErrorReceivedNativeHookDelegate^ errorReceivedDelegate_;
        GCHandle eventReceivedDelegateHookHandle_;
        GCHandle errorReceivedDelegateHookHandle_;
        GCHandle eventReceivedDelegateHandle_;
        GCHandle errorReceivedDelegateHandle_;
        void RegisterCallbacks();
    };

    // Implementation
    // ------------------------------------------------------------------------

    EventFilter::EventFilter(O365::Security::ETW::Predicate ^pred)
    : filter_(pred->to_underlying())
    {
        RegisterCallbacks();
    }

    EventFilter::EventFilter(unsigned short eventId)
        : filter_(eventId)
    {
        RegisterCallbacks();
    }

    EventFilter::EventFilter(unsigned short eventId, O365::Security::ETW::Predicate^ pred)
    : filter_(eventId, pred->to_underlying())
    {
        RegisterCallbacks();
    }

    EventFilter::EventFilter(List<unsigned short>^ eventIds)
        : filter_(to_vector(eventIds))
    {
        RegisterCallbacks();
    }

    EventFilter::EventFilter(List<unsigned short>^ eventIds, O365::Security::ETW::Predicate^ pred)
        : filter_(to_vector(eventIds), pred->to_underlying())
    {
        RegisterCallbacks();
    }

    inline EventFilter::~EventFilter()
    {
        if (eventReceivedDelegateHandle_.IsAllocated)
        {
            eventReceivedDelegateHandle_.Free();
        }

        if (eventReceivedDelegateHookHandle_.IsAllocated)
        {
            eventReceivedDelegateHookHandle_.Free();
        }

        if (errorReceivedDelegateHandle_.IsAllocated)
        {
            errorReceivedDelegateHandle_.Free();
        }

        if (errorReceivedDelegateHookHandle_.IsAllocated)
        {
            errorReceivedDelegateHookHandle_.Free();
        }
    }

    inline void EventFilter::RegisterCallbacks()
    {
        eventReceivedDelegate_ = gcnew EventReceivedNativeHookDelegate(this, &EventFilter::EventNotification);
        eventReceivedDelegateHandle_ = GCHandle::Alloc(eventReceivedDelegate_);
        auto bridgedEventDelegate = Marshal::GetFunctionPointerForDelegate(eventReceivedDelegate_);
        eventReceivedDelegateHookHandle_ = GCHandle::Alloc(bridgedEventDelegate);

        filter_->add_on_event_callback((krabs::c_provider_callback)bridgedEventDelegate.ToPointer());

        errorReceivedDelegate_ = gcnew ErrorReceivedNativeHookDelegate(this, &EventFilter::ErrorNotification);
        errorReceivedDelegateHandle_ = GCHandle::Alloc(errorReceivedDelegate_);
        auto bridgedErrorDelegate = Marshal::GetFunctionPointerForDelegate(errorReceivedDelegate_);
        errorReceivedDelegateHookHandle_ = GCHandle::Alloc(bridgedErrorDelegate);

        filter_->add_on_error_callback((krabs::c_provider_error_callback)bridgedErrorDelegate.ToPointer());
    }

    inline void EventFilter::EventNotification(const EVENT_RECORD &record, const krabs::trace_context &trace_context)
    {
        try
        {
            krabs::schema schema(record, trace_context.schema_locator);
            krabs::parser parser(schema);

            OnEvent(gcnew EventRecord(record, schema, parser));
        }
        catch (const krabs::could_not_find_schema& ex)
        {
            ErrorNotification(record, ex.what());
        }
    }

    inline void EventFilter::ErrorNotification(const EVENT_RECORD& record, const std::string& error_message)
    {
        auto msg = gcnew String(error_message.c_str());
        auto metadata = gcnew EventRecordMetadata(record);

        OnError(gcnew EventRecordError(msg, metadata));
    }

} } } }