cmake_minimum_required (VERSION 2.8)
project (hollows_hunter)
option(HH_BUILD_TESTING "enable testing for peconv" ON)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

# modules:
set ( M_PESIEVE "pe-sieve" )

# modules paths:
set (PESIEVE_DIR "${PROJECT_SOURCE_DIR}/${M_PESIEVE}" CACHE PATH "PE-sieve main path")
include_directories ( ${PESIEVE_DIR}/include )

set (srcs
	main.cpp
	term_util.cpp
)

set (hdrs
	term_util.h
)

# libs
set ( PESIEVE_AS_DLL ON CACHE BOOL "Enable building PE-sieve as a DLL" FORCE)
add_subdirectory (pe-sieve)
set ( PESIEVE_LIB $<TARGET_FILE:pe-sieve> CACHE FILE "PE-sieve library path" )

cmake_policy(SET CMP0015 NEW)
LINK_DIRECTORIES ( ${PESIEVE_LIB} )
add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} main.cpp )
target_link_libraries ( ${PROJECT_NAME} ${M_PESIEVE} )

# dependencies
add_dependencies( ${PROJECT_NAME} ${M_PESIEVE} )

# Setup testing
if(HH_BUILD_TESTING)
	enable_testing()

	# 0) does the application run
	add_test (TestRuns hollows_hunter)
endif()
