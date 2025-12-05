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

	# Ensure the test runs from the project root so relative storage-path './files'
	# resolves to the repository 'files' directory (where 3f00.def lives). This
	# avoids needing embedded static files or runtime environment changes for
	# tests that read the host filesystem.
	set_tests_properties(profile_provision_test PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

	add_test(NAME profile_provision__test_compare
		COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol
			${CMAKE_CURRENT_BINARY_DIR}/profile_provision_test.out
			${CMAKE_CURRENT_SOURCE_DIR}/profile_provision_test.ok
	)
endif(TARGET utils)
