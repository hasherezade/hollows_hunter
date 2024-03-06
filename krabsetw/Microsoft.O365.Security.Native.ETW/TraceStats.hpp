// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <krabs.hpp>

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// Selected statistics about an ETW trace
    /// </summary>
    public value class TraceStats
    {
    public:
        /// <summary>count of trace buffers</summary>
        initonly uint32_t BuffersCount;

        /// <summary>count of free buffers</summary>
        initonly uint32_t BuffersFree;

        /// <summary>count of buffers written</summary>
        initonly uint32_t BuffersWritten;

        /// <summary>count of buffers lost</summary>
        initonly uint32_t BuffersLost;

        /// <summary>count of total events</summary>
        initonly uint64_t EventsTotal;

        /// <summary>count of events handled</summary>
        initonly uint64_t EventsHandled;

        /// <summary>count of events lost</summary>
        initonly uint32_t EventsLost;

    internal:
        TraceStats(const krabs::trace_stats& stats)
            : BuffersCount(stats.buffersCount)
            , BuffersFree(stats.buffersFree)
            , BuffersWritten(stats.buffersWritten)
            , BuffersLost(stats.buffersLost)
            , EventsTotal(stats.eventsTotal)
            , EventsHandled(stats.eventsHandled)
            , EventsLost(stats.eventsLost)
        { }
    };

} } } }