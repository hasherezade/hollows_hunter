cmake_minimum_required ( VERSION 3.0 )
project ( krabs )

set (KRABS_DIR krabsetw/krabs )
set (MS_ETW krabsetw/Microsoft.O365.Security.Native.ETW)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /D_USING_V110_SDK71_")
add_definitions(-DNDEBUG -DUNICODE -D_WINDLL)
#<PreprocessorDefinitions>NDEBUG;UNICODE;_WINDLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
include_directories (
	${KRABS_DIR}
)

set (srcs_filtering
	${KRABS_DIR}/krabs/filtering/comparers.hpp
	${KRABS_DIR}/krabs/filtering/event_filter.hpp
	${KRABS_DIR}/krabs/filtering/predicates.hpp
	${KRABS_DIR}/krabs/filtering/view_adapters.hpp
)

set (srcs_testing
	${KRABS_DIR}/krabs/testing/event_filter_proxy.hpp
	${KRABS_DIR}/krabs/testing/extended_data_builder.hpp
	${KRABS_DIR}/krabs/testing/filler.hpp
	${KRABS_DIR}/krabs/testing/proxy.hpp
	${KRABS_DIR}/krabs/testing/record_builder.hpp
	${KRABS_DIR}/krabs/testing/record_property_thunk.hpp
	${KRABS_DIR}/krabs/testing/synth_record.hpp
)



set ( lib_src
    ${MS_ETW}/AssemblyInfo.cpp
    ${MS_ETW}/ETWLib.cpp
)
set ( lib_rsrc
    ${MS_ETW}/System
    ${MS_ETW}/System.Data
    ${MS_ETW}/System.Xml
)
set ( lib_hdrs
	${MS_ETW}/Conversions.hpp
	${MS_ETW}/Errors.hpp
	${MS_ETW}/EventRecordError.hpp
	${MS_ETW}/EventRecordMetadata.hpp
	${MS_ETW}/EventTraceProperties.hpp
	${MS_ETW}/Filtering/AnsiString.hpp
	${MS_ETW}/Filtering/CountedString.hpp
	${MS_ETW}/Filtering/EventFilter.hpp
	${MS_ETW}/Filtering/Fluent.hpp
	${MS_ETW}/Filtering/Predicate.hpp
	${MS_ETW}/Filtering/UnicodeString.hpp
	${MS_ETW}/Guid.hpp
	${MS_ETW}/IEventRecordError.hpp
	${MS_ETW}/IEventRecordMetadata.hpp
	${MS_ETW}/IEventRecord.hpp
	${MS_ETW}/ITrace.hpp
	${MS_ETW}/KernelProvider.hpp
	${MS_ETW}/KernelTrace.hpp
	${MS_ETW}/Kernel/KernelProviders.hpp
	${MS_ETW}/NativePtr.hpp
	${MS_ETW}/Property.hpp
	${MS_ETW}/Provider.hpp
	${MS_ETW}/EventRecord.hpp
	${MS_ETW}/RawProvider.hpp
	${MS_ETW}/Testing/EventHeader.hpp
	${MS_ETW}/Testing/RecordBuilder.hpp
	${MS_ETW}/Testing/SynthRecord.hpp
	${MS_ETW}/Testing/Proxy.hpp
	${MS_ETW}/TraceStats.hpp
	${MS_ETW}/UserTrace.hpp
)

set (srcs
	${lib_src}
	${srcs_filtering}
	${srcs_testing}
	${KRABS_DIR}/krabs/client.hpp
	${KRABS_DIR}/krabs/collection_view.hpp
	${KRABS_DIR}/krabs/compiler_check.hpp
	${KRABS_DIR}/krabs/errors.hpp
	${KRABS_DIR}/krabs/etw.hpp
	${KRABS_DIR}/krabs/guid.hpp
	${KRABS_DIR}/krabs/kernel_guids.hpp
	${KRABS_DIR}/krabs/kernel_providers.hpp
	${KRABS_DIR}/krabs/kt.hpp
	${KRABS_DIR}/krabs/parser.hpp
	${KRABS_DIR}/krabs/parse_types.hpp
	${KRABS_DIR}/krabs/perfinfo_groupmask.hpp
	${KRABS_DIR}/krabs/property.hpp
	${KRABS_DIR}/krabs/provider.hpp
	${KRABS_DIR}/krabs/schema.hpp
	${KRABS_DIR}/krabs/schema_locator.hpp
	${KRABS_DIR}/krabs/size_provider.hpp
	${KRABS_DIR}/krabs/tdh_helpers.hpp
	${KRABS_DIR}/krabs/trace.hpp
	${KRABS_DIR}/krabs/trace_context.hpp
	${KRABS_DIR}/krabs/ut.hpp
	${KRABS_DIR}/krabs/version_helpers.hpp
	${KRABS_DIR}/krabs/wstring_convert.hpp
)

set (hdrs
	${KRABS_DIR}/krabs.hpp
)

set_property (SOURCE ${KRABS_DIR}/krabs.hpp APPEND PROPERTY HEADER_FILE_ONLY true)

add_library ( ${PROJECT_NAME} ${lib_src} ${lib_hdrs} )
set_target_properties(${PROJECT_NAME} PROPERTIES LINKER_LANGUAGE CXX)