// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <krabs.hpp>

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// EventTraceProperties represents the performance characteristics
    /// for a trace session.
    /// </summary>
    public ref struct EventTraceProperties
    {
        uint32_t BufferSize;      // buffer size for logging (kbytes)
        uint32_t MinimumBuffers;  // minimum buffers to preallocate
        uint32_t MaximumBuffers;  // maximum buffers allowed
        uint32_t LogFileMode;     // sequential, circular
        uint32_t FlushTimer;      // buffer flush timer, in seconds
    };

    /// <summary>
    /// LogFileModeFlags enumerates the options for EventTraceProperties.LogFileMode
    /// </summary>
    public enum class LogFileModeFlags : uint32_t
    {
        FLAG_EVENT_TRACE_FILE_MODE_NONE        = 0x00000000, // Logfile is off
        FLAG_EVENT_TRACE_FILE_MODE_SEQUENTIAL  = 0x00000001, // Log sequentially
        FLAG_EVENT_TRACE_FILE_MODE_CIRCULAR    = 0x00000002, // Log in circular manner
        FLAG_EVENT_TRACE_FILE_MODE_APPEND      = 0x00000004, // Append sequential log
        FLAG_EVENT_TRACE_REAL_TIME_MODE        = 0x00000100, // Real time mode on
        FLAG_EVENT_TRACE_DELAY_OPEN_FILE_MODE  = 0x00000200, // Delay opening file
        FLAG_EVENT_TRACE_BUFFERING_MODE        = 0x00000400, // Buffering mode only
        FLAG_EVENT_TRACE_PRIVATE_LOGGER_MODE   = 0x00000800, // Process Private Logger
        FLAG_EVENT_TRACE_ADD_HEADER_MODE       = 0x00001000, // Add a logfile header
        FLAG_EVENT_TRACE_USE_GLOBAL_SEQUENCE   = 0x00004000, // Use global sequence no.
        FLAG_EVENT_TRACE_USE_LOCAL_SEQUENCE    = 0x00008000, // Use local sequence no.
        FLAG_EVENT_TRACE_RELOG_MODE            = 0x00010000, // Relogger
        FLAG_EVENT_TRACE_USE_PAGED_MEMORY      = 0x01000000, // Use pageable buffers

        //
        // Logger Mode flags on XP and above
        //
        FLAG_EVENT_TRACE_FILE_MODE_NEWFILE     = 0x00000008, // Auto-switch log file
        FLAG_EVENT_TRACE_FILE_MODE_PREALLOCATE = 0x00000020, // Pre-allocate mode

        //
        // Logger Mode flags on Vista and above
        //
        FLAG_EVENT_TRACE_NONSTOPPABLE_MODE     = 0x00000040, // Session cannot be stopped (Autologger only)
        FLAG_EVENT_TRACE_SECURE_MODE           = 0x00000080, // Secure session
        FLAG_EVENT_TRACE_USE_KBYTES_FOR_SIZE   = 0x00002000, // Use KBytes as file size unit
        FLAG_EVENT_TRACE_PRIVATE_IN_PROC       = 0x00020000, // In process private logger
        FLAG_EVENT_TRACE_MODE_RESERVED         = 0x00100000, // Reserved bit, used to signal Heap/Critsec tracing

        //
        // Logger Mode flags on Win7 and above
        //
        FLAG_EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING = 0x10000000, // Use this for low frequency sessions

        //
        // Logger Mode flags on Win8 and above
        //
        FLAG_EVENT_TRACE_SYSTEM_LOGGER_MODE         = 0x02000000, // Receive events from SystemTraceProvider
        FLAG_EVENT_TRACE_ADDTO_TRIAGE_DUMP          = 0x80000000, // Add ETW buffers to triage dumps
        FLAG_EVENT_TRACE_STOP_ON_HYBRID_SHUTDOWN    = 0x00400000, // Stop on hybrid shutdown
        FLAG_EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN = 0x00800000, // Persist on hybrid shutdown

        //
        // Logger Mode flags on Blue and above
        //
        FLAG_EVENT_TRACE_INDEPENDENT_SESSION_MODE   = 0x08000000, // Independent logger session

        //
        // Logger Mode flags on Redstone and above
        //
        FLAG_EVENT_TRACE_COMPRESSED_MODE            = 0x04000000 // Compressed logger session
    };

} } } }