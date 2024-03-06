// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include "../UserTrace.hpp"
#include "../KernelTrace.hpp"
#include "SynthRecord.hpp"


namespace Microsoft { namespace O365 { namespace Security { namespace ETW { namespace Testing {


    /// <summary>
    /// Serves as a stand-in for the trace class for testing purposes. It acts
    /// as a liason for the actual trace instance and allows for forced event
    /// testing.
    /// </summary>
    public ref class Proxy {
    public:

        /// <summary>
        /// Constructs a proxy for the given user trace.
        /// </summary>
        Proxy(UserTrace ^trace);

        /// <summary>
        /// Constructs a proxy for the given kernel trace.
        /// </summary>
        Proxy(KernelTrace ^trace);

        /// <summary>
        /// Constructs a proxy for an event filter.
        /// </summary>
        Proxy(EventFilter ^filter);

        /// <summary>
        /// Pushes an event through the proxied trace instance.
        /// </summary>
        void PushEvent(SynthRecord ^record);

    internal:
        UserTrace ^userTrace_;
        KernelTrace ^kernelTrace_;
        EventFilter ^filter_;
    };

    // Implementation
    // ------------------------------------------------------------------------

    inline Proxy::Proxy(UserTrace ^trace)
    : userTrace_(trace)
    , kernelTrace_(nullptr)
    , filter_(nullptr)
    {}

    inline Proxy::Proxy(KernelTrace ^trace)
    : userTrace_(nullptr)
    , kernelTrace_(trace)
    , filter_(nullptr)
    {}

    inline Proxy::Proxy(EventFilter ^filter)
    : userTrace_(nullptr)
    , kernelTrace_(nullptr)
    , filter_(filter)
    {}

    inline void Proxy::PushEvent(SynthRecord ^record)
    {
        auto rec = record->record_.Get();

        if (userTrace_) {
            krabs::testing::trace_proxy<krabs::user_trace> proxy(*userTrace_->trace_.Get());
            proxy.push_event(*rec);
        }

        if (kernelTrace_) {
            krabs::testing::trace_proxy<krabs::kernel_trace> proxy(*kernelTrace_->trace_.Get());
            proxy.push_event(*rec);
        }

        if (filter_) {
            krabs::testing::event_filter_proxy proxy(*filter_->filter_.Get());
            proxy.push_event(*rec);
        }
    }
} /* namespace Testing */ } /* namespace ETW */ } /* namespace Security */ } /* namespace O365 */ } /* namespace Microsoft */