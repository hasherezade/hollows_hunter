// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <krabs/kernel_providers.hpp>

namespace Microsoft { namespace O365 { namespace Security { namespace ETW { namespace Kernel {

#define CREATE_CONVENIENCE_KERNEL_PROVIDER(__name__, __value__, __guid__)     \
    public ref class __name__ : public KernelProvider {                       \
    public:                                                                   \
        __name__()                                                            \
        : KernelProvider(__value__, __guid__)                                 \
        {}                                                                    \
    };

#define CREATE_CONVENIENCE_KERNEL_PROVIDER_MASK(__name__, __guid__, __mask__) \
    public ref class __name__ : public KernelProvider {                       \
    public:                                                                   \
        __name__()                                                            \
        : KernelProvider(__guid__, __mask__)                                  \
        {}                                                                    \
    };

    /// <summary>Converts a GUID to a Guid</summary>
    Guid FromGuid(const GUID &guid)
    {
        return Guid(guid.Data1, guid.Data2, guid.Data3,
            guid.Data4[0], guid.Data4[1],
            guid.Data4[2], guid.Data4[3],
            guid.Data4[4], guid.Data4[5],
            guid.Data4[6], guid.Data4[7]);
    }

    /// <summary>A provider that enables ALPC events.</summary>
    CREATE_CONVENIENCE_KERNEL_PROVIDER(
        AlpcProvider,
        EVENT_TRACE_FLAG_ALPC,
        FromGuid(krabs::guids::alpc));

    /// <summary>A provider that enables context switch events.</summary>
    CREATE_CONVENIENCE_KERNEL_PROVIDER(
        ContextSwitchProvider,
        EVENT_TRACE_FLAG_CSWITCH,
        FromGuid(krabs::guids::thread));

    /// <summary>A provider that enables debug print events.</summary>
    CREATE_CONVENIENCE_KERNEL_PROVIDER(
        DebugPrintProvider,
        EVENT_TRACE_FLAG_DBGPRINT,
        FromGuid(krabs::guids::debug));

    /// <summary>A provider that enables file I/O name events.</summary>
    CREATE_CONVENIENCE_KERNEL_PROVIDER(
        DiskFileIoProvider,
        EVENT_TRACE_FLAG_DISK_FILE_IO,
        FromGuid(krabs::guids::file_io));

    /// <summary>A provider that enables disk I/O completion events.</summary>
    CREATE_CONVENIENCE_KERNEL_PROVIDER(
        DiskIoProvider,
        EVENT_TRACE_FLAG_DISK_IO,
        FromGuid(krabs::guids::disk_io));

    /// <summary>A provider that enables beginning of disk I/O events.</summary>
    CREATE_CONVENIENCE_KERNEL_PROVIDER(
        DiskInitIoProvider,
        EVENT_TRACE_FLAG_DISK_IO_INIT,
        FromGuid(krabs::guids::disk_io));

    /// <summary>A provider that enables file I/O completion events.</summary>
    CREATE_CONVENIENCE_KERNEL_PROVIDER(
        FileIoProvider,
        EVENT_TRACE_FLAG_FILE_IO,
        FromGuid(krabs::guids::file_io));

    /// <summary>A provider that enables file I/O events.</summary>
    CREATE_CONVENIENCE_KERNEL_PROVIDER(
        FileInitIoProvider,
        EVENT_TRACE_FLAG_FILE_IO_INIT,
        FromGuid(krabs::guids::file_io));

    /// <summary>A provider that enables thread dispatch events.</summary>
    CREATE_CONVENIENCE_KERNEL_PROVIDER(
        ThreadDispatchProvider,
        EVENT_TRACE_FLAG_DISPATCHER,
        FromGuid(krabs::guids::thread));

    /// <summary>A provider that enables device deferred procedure call events.</summary>
    CREATE_CONVENIENCE_KERNEL_PROVIDER(
        DpcProvider,
        EVENT_TRACE_FLAG_DPC,
        FromGuid(krabs::guids::perf_info));

    /// <summary>A provider that enables driver events.</summary>
    CREATE_CONVENIENCE_KERNEL_PROVIDER(
        DriverProvider,
        EVENT_TRACE_FLAG_DRIVER,
        FromGuid(krabs::guids::disk_io));

    /// <summary>A provider that enables image load events.</summary>
    CREATE_CONVENIENCE_KERNEL_PROVIDER(
        ImageLoadProvider,
        EVENT_TRACE_FLAG_IMAGE_LOAD,
        FromGuid(krabs::guids::image_load));

    /// <summary>A provider that enables interrupt events.</summary>
    CREATE_CONVENIENCE_KERNEL_PROVIDER(
        InterruptProvider,
        EVENT_TRACE_FLAG_INTERRUPT,
        FromGuid(krabs::guids::perf_info));

    /// <summary>A provider that enables memory hard fault events.</summary>
    CREATE_CONVENIENCE_KERNEL_PROVIDER(
        MemoryHardFaultProvider,
        EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS,
        FromGuid(krabs::guids::page_fault));

    /// <summary>A provider that enables memory page fault events.</summary>
    CREATE_CONVENIENCE_KERNEL_PROVIDER(
        MemoryPageFaultProvider,
        EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS,
        FromGuid(krabs::guids::page_fault));

    /// <summary>A provider that enables network tcp/ip events.</summary>
    CREATE_CONVENIENCE_KERNEL_PROVIDER(
        NetworkTcpipProvider,
        EVENT_TRACE_FLAG_NETWORK_TCPIP,
        FromGuid(krabs::guids::tcp_ip));

    /// <summary>A provider that enables process events.</summary>
    CREATE_CONVENIENCE_KERNEL_PROVIDER(
        ProcessProvider,
        EVENT_TRACE_FLAG_PROCESS,
        FromGuid(krabs::guids::process));

    /// <summary>A provider that enables process counter events.</summary>
    CREATE_CONVENIENCE_KERNEL_PROVIDER(
        ProcessCounterProvider,
        EVENT_TRACE_FLAG_PROCESS_COUNTERS,
        FromGuid(krabs::guids::process));

    /// <summary>A provider that enables profiling events.</summary>
    CREATE_CONVENIENCE_KERNEL_PROVIDER(
        ProfileProvider,
        EVENT_TRACE_FLAG_PROFILE,
        FromGuid(krabs::guids::perf_info));

    /// <summary>A provider that enables registry events.</summary>
    CREATE_CONVENIENCE_KERNEL_PROVIDER(
        RegistryProvider,
        EVENT_TRACE_FLAG_REGISTRY,
        FromGuid(krabs::guids::registry));

    /// <summary>A provider that enables split I/O events.</summary>
    CREATE_CONVENIENCE_KERNEL_PROVIDER(
        SplitIoProvider,
        EVENT_TRACE_FLAG_SPLIT_IO,
        FromGuid(krabs::guids::split_io));

    /// <summary>A provider that enables system call events.</summary>
    CREATE_CONVENIENCE_KERNEL_PROVIDER(
        SystemCallProvider,
        EVENT_TRACE_FLAG_SYSTEMCALL,
        FromGuid(krabs::guids::system_trace));

    /// <summary>A provider that enables thread start and stop events.</summary>
    CREATE_CONVENIENCE_KERNEL_PROVIDER(
        ThreadProvider,
        EVENT_TRACE_FLAG_THREAD,
        FromGuid(krabs::guids::thread));

    /// <summary>A provider that enables file map and unmap (excluding images) events.</summary>
    CREATE_CONVENIENCE_KERNEL_PROVIDER(
        VaMapProvider,
        EVENT_TRACE_FLAG_VAMAP,
        FromGuid(krabs::guids::file_io));

    /// <summary>A provider that enables VirtualAlloc and VirtualFree events.</summary>
    CREATE_CONVENIENCE_KERNEL_PROVIDER(
        VirtualAllocProvider,
        EVENT_TRACE_FLAG_VIRTUAL_ALLOC,
        FromGuid(krabs::guids::page_fault));

    /// <summary>A provider that enables Object Manager events.</summary>
    CREATE_CONVENIENCE_KERNEL_PROVIDER_MASK(
        ObjectManagerProvider,
        FromGuid(krabs::guids::ob_trace),
        PERF_OB_HANDLE);

#undef CREATE_CONVENIENCE_KERNEL_PROVIDER
#undef CREATE_CONVENIENCE_KERNEL_PROVIDER_MASK

} } } } }