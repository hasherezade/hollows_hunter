cmake_minimum_required (VERSION 3.0)
project (hollows_hunter)

option(HH_BUILD_TESTING "Enable testing for HollowsHunter" ON)
option (PECONV_LIB_INSTALL OFF)
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
option( USE_ETW "Use ETW" ON )
if(USE_ETW)
    add_compile_definitions(USE_ETW)
	#FYI Krabs need to be built as a static lib which is not the default from the submodule 
endif()

# static linking for GNU compilers
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")

	if(LINK_STATICALLY)
		add_link_options(
			-static
			-static-libgcc
			-static-libstdc++
		)
	endif()

endif()

# modules:
set ( M_PESIEVE "pe-sieve" )
set ( M_PARAMKIT "paramkit" )


# modules paths:
set (PESIEVE_DIR "${PROJECT_SOURCE_DIR}/${M_PESIEVE}" CACHE PATH "PE-sieve main path")
include_directories ( ${PESIEVE_DIR}/include )

set (PARAMKIT_DIR "${CMAKE_SOURCE_DIR}/${M_PARAMKIT}/${M_PARAMKIT}" CACHE PATH "ParamKit main path" )
include_directories ( ${PARAMKIT_DIR}/include )

set (srcs
	main.cpp
	term_util.cpp
	hh_scanner.cpp
	hh_params.cpp
	hh_report.cpp
	params_info/pe_sieve_params_info.cpp
	util/suspend.cpp
	util/process_privilege.cpp
	util/time_util.cpp
	util/strings_util.cpp
)

set (hdrs
	term_util.h
	hh_scanner.h
	hh_params.h
	hh_report.h
	params_info/params.h
	params_info/pe_sieve_params_info.h
	util/suspend.h
	util/ntddk.h
	util/process_privilege.h
	util/time_util.h
	util/strings_util.h
	util/process_util.h
)

if(USE_ETW)
	set (srcs
		${srcs}
		etw_listener.cpp
	)

	set (hdrs
		${hdrs}
		etw_listener.h
		krabsetw/krabs/krabs.hpp
	)
endif()

set (rsrc
	resources.h
	hh_res.rc
	hh_ver_short.h
)

# libs
if (NOT PESIEVE_AS_DLL)
	set ( PESIEVE_AS_STATIC_LIB ON CACHE BOOL "Enable building PE-sieve as a static library" FORCE)
endif()

if (NOT PESIEVE_AS_STATIC_LIB)
	set ( PESIEVE_AS_DLL ON CACHE BOOL "Enable building PE-sieve as a DLL" FORCE)
endif()

add_subdirectory ( ${PESIEVE_DIR} )
set ( PESIEVE_LIB $<TARGET_FILE:pe-sieve> CACHE PATH "PE-sieve library path" )

add_subdirectory ( ${PARAMKIT_DIR} )
set ( PARAMKIT_LIB $<TARGET_FILE:paramkit> CACHE PATH "ParamKit library path" )

cmake_policy(SET CMP0015 NEW)
LINK_DIRECTORIES ( ${PESIEVE_LIB} )
add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} ${rsrc} main.cpp )
target_link_libraries ( ${PROJECT_NAME} ${M_PESIEVE} ${M_PARAMKIT} "psapi.lib" "ntdll.lib")

# dependencies
add_dependencies( ${PROJECT_NAME} ${M_PESIEVE} ${M_PARAMKIT} )
target_compile_definitions(${PROJECT_NAME} PUBLIC -DUNICODE)
target_compile_definitions(${M_PARAMKIT} PUBLIC -DUNICODE)
#install
INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )

# Setup testing
if(HH_BUILD_TESTING)
	enable_testing()
	
	# 0) does the application run
	add_test (TestRuns ${CMAKE_INSTALL_PREFIX}/hollows_hunter -?)
	set_tests_properties(TestRuns PROPERTIES PASS_REGULAR_EXPRESSION "HollowsHunter")
	
	# 1) false positives in a clean environment
	add_test (TestFalsePositives ${CMAKE_INSTALL_PREFIX}/hollows_hunter -json -dir scan_out)
	set_tests_properties(TestFalsePositives PROPERTIES PASS_REGULAR_EXPRESSION "\"suspicious_count\" : 0")

	# 2) test scan with caching
	add_test (TestCaching ${CMAKE_INSTALL_PREFIX}/hollows_hunter -json -dir scan_out -cache)
	set_tests_properties(TestCaching PROPERTIES PASS_REGULAR_EXPRESSION "\"suspicious_count\" : 0")

	# 3) test scan IAT with caching
	add_test (TestIatScan ${CMAKE_INSTALL_PREFIX}/hollows_hunter -json -dir scan_out -cache -iat 1)
	set_tests_properties(TestIatScan PROPERTIES PASS_REGULAR_EXPRESSION "\"suspicious_count\" : ")

	# 4) test scan hooks with caching
	add_test (TestHooksScan ${CMAKE_INSTALL_PREFIX}/hollows_hunter -json -dir scan_out -cache -hooks)
	set_tests_properties(TestHooksScan PROPERTIES PASS_REGULAR_EXPRESSION "\"suspicious_count\" : ")

	# 5) test scan threads with caching
	add_test (TestThreadsScan ${CMAKE_INSTALL_PREFIX}/hollows_hunter -json -dir scan_out -cache -threads)
	set_tests_properties(TestThreadsScan PROPERTIES PASS_REGULAR_EXPRESSION "\"suspicious_count\" : ")

	# 6) test scan code patterns with caching
	add_test (TestCodeScanNoDump ${CMAKE_INSTALL_PREFIX}/hollows_hunter -json -dir scan_out -cache -shellc P -ofilter 2)
	set_tests_properties(TestCodeScanNoDump PROPERTIES PASS_REGULAR_EXPRESSION "\"suspicious_count\" : ")
endif()
