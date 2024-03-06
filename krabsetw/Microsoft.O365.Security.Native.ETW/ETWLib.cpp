// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This is the main DLL file.

#include "Guid.hpp"
#include "Errors.hpp"
#include "UserTrace.hpp"
#include "TraceStats.hpp"
#include "Provider.hpp"
#include "RawProvider.hpp"
#include "KernelProvider.hpp"
#include "ITrace.hpp"
#include "IEventRecordMetadata.hpp"
#include "IEventRecord.hpp"
#include "EventRecordMetadata.hpp"
#include "EventRecord.hpp"
#include "EventRecordError.hpp"
#include "Property.hpp"

#include "Filtering/Predicate.hpp"
#include "Filtering/EventFilter.hpp"
#include "Filtering/Fluent.hpp"
#include "Filtering/UnicodeString.hpp"
#include "Filtering/AnsiString.hpp"
#include "Filtering/CountedString.hpp"

#include "KernelProvider.hpp"
#include "KernelTrace.hpp"
#include "Kernel/KernelProviders.hpp"

#include "Testing/EventHeader.hpp"
#include "Testing/SynthRecord.hpp"
#include "Testing/RecordBuilder.hpp"
#include "Testing/Proxy.hpp"
