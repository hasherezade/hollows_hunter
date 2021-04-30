cmake_minimum_required (VERSION 2.8)
project (hollows_hunter)

option(HH_BUILD_TESTING "Enable testing for HollowsHunter" ON)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

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

# modules paths:
set (PESIEVE_DIR "${PROJECT_SOURCE_DIR}/${M_PESIEVE}" CACHE PATH "PE-sieve main path")
include_directories ( ${PESIEVE_DIR}/include )

set (srcs
	main.cpp
	term_util.cpp
	hh_scanner.cpp
	hh_params.cpp
	hh_report.cpp
	params_info/pe_sieve_params_info.cpp
	params_info/pe_sieve_params_print.cpp
	util/suspend.cpp
	util/util.cpp
	util/process_privilege.cpp
	util/time_util.cpp
	util/strings_util.cpp
)

set (hdrs
	term_util.h
	color_scheme.h
	hh_scanner.h
	hh_params.h
	hh_report.h
	params_info/param_base.h
	params_info/params_list.h
	params_info/pe_sieve_params_info.h
	params_info/pe_sieve_params_print.h
	util/suspend.h
	util/ntddk.h
	util/util.h
	util/process_privilege.h
	util/time_util.h
	util/strings_util.h
)

# libs
if (NOT PESIEVE_AS_STATIC_LIB)
	set ( PESIEVE_AS_DLL ON CACHE BOOL "Enable building PE-sieve as a DLL" FORCE)
endif()

add_subdirectory (pe-sieve)
set ( PESIEVE_LIB $<TARGET_FILE:pe-sieve> CACHE PATH "PE-sieve library path" )

cmake_policy(SET CMP0015 NEW)
LINK_DIRECTORIES ( ${PESIEVE_LIB} )
add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} main.cpp )
target_link_libraries ( ${PROJECT_NAME} ${M_PESIEVE} "psapi.lib" "ntdll.lib")

# dependencies
add_dependencies( ${PROJECT_NAME} ${M_PESIEVE} )

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
	set_tests_properties(TestFalsePositives PROPERTIES PASS_REGULAR_EXPRESSION "\"susipcious_count\" : 0")
endif()
