# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(utils_test utils_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(utils_test uicc)

add_test(NAME utils_test COMMAND sh -c "$<TARGET_FILE:utils_test> > utils_test.out")

add_test(NAME utils_test_compare
		 COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol
				 ${CMAKE_CURRENT_BINARY_DIR}/utils_test.out
				 ${CMAKE_CURRENT_SOURCE_DIR}/utils_test.ok
)

if(TARGET utils)
	# Test of general utils functions, different from uicc helper functions
	add_executable(profile_decode profile_decode_test.c)

	target_link_libraries(profile_decode uicc utils)

	add_test(NAME profile_decode_test COMMAND sh -c "$<TARGET_FILE:profile_decode> > profile_decode_test.out")

	add_test(NAME profile_test_compare
		 	COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol
				 	${CMAKE_CURRENT_BINARY_DIR}/profile_decode_test.out
				 	${CMAKE_CURRENT_SOURCE_DIR}/profile_decode_test.ok
	)

	#Test of profile provisioning
	add_executable(profile_provision_test profile_provision_test.c)

	target_link_libraries(profile_provision_test uicc utils storage)

	add_test(NAME profile_provision_test COMMAND sh -c "$<TARGET_FILE:profile_provision_test> > ${CMAKE_CURRENT_BINARY_DIR}/profile_provision_test.out")

	# This test provisions into the storage tree, and the storage path './files'
	# resolves against the working directory. Run it against a snapshot taken at
	# configure time, as tests/key_scrub does, so a run rewrites keys in the build
	# directory rather than in the tracked files/.
	file(COPY ${CMAKE_SOURCE_DIR}/files DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/pristine)

	# Refreshed before each run, so repeated ctest invocations start from the same
	# tree and the test does not have to undo its own writes.
	add_test(NAME profile_provision_test_setup
		COMMAND ${CMAKE_COMMAND} -E copy_directory
			${CMAKE_CURRENT_BINARY_DIR}/pristine/files
			${CMAKE_CURRENT_BINARY_DIR}/files
	)
	set_tests_properties(profile_provision_test_setup PROPERTIES FIXTURES_SETUP profile_provision_files)
	set_tests_properties(profile_provision_test PROPERTIES
		FIXTURES_REQUIRED profile_provision_files
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

	add_test(NAME profile_provision_test_compare
		COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol
			${CMAKE_CURRENT_BINARY_DIR}/profile_provision_test.out
			${CMAKE_CURRENT_SOURCE_DIR}/profile_provision_test.ok
	)

	# Provisioning against the compact (binary) storage backend. Like
	# tests/storage_compact, the backend is compiled in directly, together with
	# the profile utils built for it, since the storage and utils libraries of
	# this configuration are built for the hex backend.
	add_executable(profile_provision_compact_test profile_provision_compact_test.c
		${PROJECT_SOURCE_DIR}/utils/ss_profile.c
		${PROJECT_SOURCE_DIR}/utils/ss_provision.c
		${PROJECT_SOURCE_DIR}/src/softsim/storage_compact.c
		${PROJECT_SOURCE_DIR}/src/softsim/fs.c
	)
	target_compile_definitions(profile_provision_compact_test PRIVATE CONFIG_COMPACT_STORAGE)
	target_link_libraries(profile_provision_compact_test uicc)

	add_test(NAME profile_provision_compact_test
		COMMAND sh -c "$<TARGET_FILE:profile_provision_compact_test> > ${CMAKE_CURRENT_BINARY_DIR}/profile_provision_compact_test.out")
	set_tests_properties(profile_provision_compact_test PROPERTIES WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

	add_test(NAME profile_provision_compact_test_compare
		COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol
			${CMAKE_CURRENT_BINARY_DIR}/profile_provision_compact_test.out
			${CMAKE_CURRENT_SOURCE_DIR}/profile_provision_compact_test.ok
	)
	set_tests_properties(profile_provision_compact_test_compare PROPERTIES DEPENDS profile_provision_compact_test)
endif(TARGET utils)
