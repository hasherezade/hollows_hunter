// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include "EventTraceProperties.hpp"
#include "KernelProvider.hpp"
#include "Provider.hpp"
#include "RawProvider.hpp"
#include "TraceStats.hpp"

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// Represents a instance of an ETW trace session.
    /// </summary>
    public interface class ITrace
    {
    public:
        /// <summary>
        /// Sets the trace properties for a session.
        /// Must be called before Open()/Start().
        /// </summary>
        void SetTraceProperties(EventTraceProperties^ properties);

        /// <summary>
        /// Starts listening for events from the enabled providers.
        /// </summary>
        void Start();

        /// <summary>
        /// Stops listening for events.
        /// </summary>
        void Stop();

        /// <summary>
        /// Get stats about events handled by this trace.
        /// </summary>
        /// <returns>a <see cref="O365::Security::ETW::TraceStats"/> object representing the stats of the current trace</returns>
        TraceStats QueryStats();
    };

    /// <summary>
    /// User ETW trace specific interface of <see cref="O365::Security::ETW::ITrace"/>
    /// </summary>
    public interface class IUserTrace : public ITrace
    {
    public:
        /// <summary>
        /// Enables a provider for the given user trace.
        /// </summary>
        /// <param name="provider">The <see cref="O365::Security::ETW::Provider"/> to enable.</param>
        void Enable(Provider^ provider);

        /// <summary>
        /// Enables a raw provider for the given user trace.
        /// </summary>
        /// <param name="provider">The <see cref="O365::Security::ETW::RawProvider"/> to enable.</param>
        void Enable(RawProvider^ provider);
    };

    /// <summary>
    /// Kernel ETW trace specific interface of <see cref="O365::Security::ETW::ITrace"/>
    /// </summary>
    public interface class IKernelTrace : public ITrace
    {
    public:
        /// <summary>
        /// Enables a provider for the given trace.
        /// </summary>
        /// <param name="provider">The <see cref="O365::Security::ETW::KernelProvider"/> to enable.</param>
        void Enable(KernelProvider^ provider);
    };

} } } }