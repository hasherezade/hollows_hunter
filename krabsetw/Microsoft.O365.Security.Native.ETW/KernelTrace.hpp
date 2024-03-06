// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <msclr\marshal.h>
#include <msclr\marshal_cppstd.h>

#include <krabs.hpp>

#include "ITrace.hpp"
#include "NativePtr.hpp"
#include "Provider.hpp"
#include "KernelProvider.hpp"
#include "Errors.hpp"
#include "TraceStats.hpp"

using namespace System;
using namespace System::Runtime::InteropServices;

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// Represents an owned user trace.
    /// </summary>
    public ref class KernelTrace : public IKernelTrace, public IDisposable {
    public:

        /// <summary>
        /// Constructs a kernel trace session with a generated name (or the
        /// required kernel trace name on pre-Win8 machines)
        /// </summary>
        /// <example>
        ///     KernelTrace trace = new KernelTrace();
        /// </example>
        KernelTrace();

        /// <summary>
        /// Stops the trace when disposed.
        /// </summary>
        ~KernelTrace();

        /// <summary>
        /// Constructs a named kernel trace session, where the name can be
        /// any arbitrary, unique string. On pre-Win8 machines, the trace name
        /// will be the required kernel trace name and not the given one.
        /// </summary>
        /// <param name="name">the name to use for the trace</param>
        /// <example>
        ///     KernelTrace trace = new KernelTrace("Purdy kitty");
        /// </example>
        KernelTrace(String^ name);

        /// <summary>
        /// Enables a provider for the given trace.
        /// </summary>
        /// <param name="provider">
        /// the <see cref="O365::Security::ETW::KernelProvider"/> to
        /// register with the current trace object
        /// </param>
        /// <example>
        ///     KernelTrace trace = new KernelTrace();
        ///     KernelProvider provider = new Kernel.NetworkTcpipProvider()
        ///     trace.Enable(provider);
        /// </example>
        virtual void Enable(O365::Security::ETW::KernelProvider ^provider);

        /// <summary>
        /// Sets the trace properties for a session.
        /// Must be called before Open()/Start().
        /// See https://docs.microsoft.com/en-us/windows/win32/etw/event-trace-properties
        /// for important details and restrictions.
        ///
        /// Configurable properties are ->
        ///  - BufferSize. In KB. The maximum buffer size is 1024 KB.
        ///  - MinimumBuffers. Minimum number of buffers is two per processor* .
        ///  - MaximumBuffers.
        ///  - FlushTimer. How often, in seconds, the trace buffers are forcibly flushed.
        ///  - LogFileMode. EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING simulates a *single* sequential processor.
        /// </summary>
        /// <param name="properties">the <see cref="O365::Security::ETW::EventTraceProperties"/> to set on the trace</param>
        /// <example>
        ///     var trace = new KernelTrace();
        ///     var properties = new EventTraceProperties
        ///     {
        ///         BufferSize = 256,
        ///         LogFileMode = (uint)LogFileModeFlags.FLAG_EVENT_TRACE_REAL_TIME_MODE
        ///     };
        ///     trace.SetTraceProperties(properties);
        ///     // ...
        ///     trace.Start();
        /// </example>
        virtual void SetTraceProperties(EventTraceProperties^ properties);

        /// <summary>
        /// Opens a trace session.
        /// </summary>
        /// <example>
        ///     var trace = new KernelTrace();
        ///     // ...
        ///     trace.Open();
        ///     // ...
        ///     trace.Start();
        /// </example>
        /// <remarks>
        /// This is an optional call before Start() if you need the trace
        /// registered with the ETW subsystem before you start processing events.
        /// </remarks>
        virtual void Open();

        /// <summary>
        /// Starts listening for events from the enabled providers.
        /// </summary>
        /// <example>
        ///     KernelTrace trace = new KernelTrace();
        ///     // ...
        ///     trace.Start();
        /// </example>
        /// <remarks>
        /// This function is a blocking call. Whichever thread calls Start() is effectively
        /// donating itself to the ETW subsystem as the processing thread for events.
        ///
        /// A side effect of this is that it is expected that Stop() will be called on
        /// a different thread.
        /// </remarks>
        virtual void Start();

        /// <summary>
        /// Stops listening for events.
        /// </summary>
        /// <example>
        ///     KernelTrace trace = new KernelTrace();
        ///     // ...
        ///     trace.Start();
        ///     trace.Stop();
        /// </example>
        virtual void Stop();

        /// <summary>
        /// Get stats about events handled by this trace
        /// </summary>
        /// <returns>a <see cref="O365::Security::ETW::TraceStats"/> object representing the stats of the current trace</returns>
        virtual TraceStats QueryStats();

        /// <summary>
        /// Adds a function to call when an event is fired which has no corresponding provider.
        /// </summary>
        /// <param name="callback">the function to call into</param>
        /// <example>
        ///     KernelTrace trace = new KernelTrace();
        ///     trace.SetDefaultEventCallback((record) => { ... });
        /// </example>
        virtual void SetDefaultEventCallback(IEventRecordDelegate^ callback);

    internal:
        bool disposed_ = false;
        O365::Security::ETW::NativePtr<krabs::kernel_trace> trace_;

        IEventRecordDelegate^ callback_;
        void EventNotification(const EVENT_RECORD&, const krabs::trace_context&);
        delegate void NativeHookDelegate(const EVENT_RECORD&, const krabs::trace_context&);
        NativeHookDelegate^ del_;
        GCHandle delegateHandle_;
        GCHandle delegateHookHandle_;
    };

    // Implementation
    // ------------------------------------------------------------------------

    inline KernelTrace::KernelTrace()
        : trace_(new krabs::kernel_trace())
    { }

    inline KernelTrace::~KernelTrace()
    {
        if (disposed_) {
            return;
        }

        Stop();
        disposed_ = true;

        if (delegateHandle_.IsAllocated)
        {
            delegateHandle_.Free();
        }

        if (delegateHookHandle_.IsAllocated)
        {
            delegateHookHandle_.Free();
        }
    }

    inline KernelTrace::KernelTrace(String ^name)
        : trace_()
    {
        std::wstring nativeName = msclr::interop::marshal_as<std::wstring>(name);
        trace_.Swap(O365::Security::ETW::NativePtr<krabs::kernel_trace>(nativeName));
    }

    inline void KernelTrace::Enable(O365::Security::ETW::KernelProvider ^provider)
    {
        return trace_->enable(*provider->provider_);
    }

    inline void KernelTrace::SetTraceProperties(EventTraceProperties^ properties)
    {
        EVENT_TRACE_PROPERTIES _properties;
        _properties.BufferSize = properties->BufferSize;
        _properties.MinimumBuffers = properties->MinimumBuffers;
        _properties.MaximumBuffers = properties->MaximumBuffers;
        _properties.LogFileMode = properties->LogFileMode;
        _properties.FlushTimer = properties->FlushTimer;
        ExecuteAndConvertExceptions(return trace_->set_trace_properties(&_properties));
    }

    inline void KernelTrace::Open()
    {
        ExecuteAndConvertExceptions((void)trace_->open());
    }

    inline void KernelTrace::Start()
    {
        ExecuteAndConvertExceptions(return trace_->start());
    }

    inline void KernelTrace::Stop()
    {
        ExecuteAndConvertExceptions(return trace_->stop());
    }

    inline TraceStats KernelTrace::QueryStats()
    {
        ExecuteAndConvertExceptions(return TraceStats(trace_->query_stats()));
    }

    inline void KernelTrace::SetDefaultEventCallback(IEventRecordDelegate^ callback)
    {
        callback_ = callback;

        if (!delegateHandle_.IsAllocated) {
            del_ = gcnew NativeHookDelegate(this, &KernelTrace::EventNotification);
            delegateHandle_ = GCHandle::Alloc(del_);
            auto bridged = Marshal::GetFunctionPointerForDelegate(del_);
            delegateHookHandle_ = GCHandle::Alloc(bridged);
            ExecuteAndConvertExceptions((void)trace_->set_default_event_callback((krabs::c_provider_callback)bridged.ToPointer()));
        }
    }

    inline void KernelTrace::EventNotification(const EVENT_RECORD& record, const krabs::trace_context& trace_context)
    {
            krabs::schema schema(record, trace_context.schema_locator);
            krabs::parser parser(schema);
            callback_(gcnew EventRecord(record, schema, parser));
    }

} } } }