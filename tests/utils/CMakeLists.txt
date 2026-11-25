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

	# Profile provisioning, one source run against every storage layout: hex or
	# compact (binary) EFs, in a directory tree or flat with the '_' file
	# separator. Every variant prints the same output and is compared against the
	# same .ok file.
	#
	# The default variant links the utils and storage libraries as this
	# configuration builds them. The others compile the profile utils and the
	# storage backend in directly, with their own definitions, as
	# tests/storage_compact does, since the libraries are built for one layout.
	add_executable(profile_provision_test profile_provision_test.c)
	target_link_libraries(profile_provision_test uicc utils storage)

	set(profile_provision_variants
		"profile_provision_compact_test\;CONFIG_COMPACT_STORAGE\;storage_compact.c"
		"profile_provision_flat_test\;CONFIG_ALT_FILE_SEPARATOR\;storage.c"
		"profile_provision_compact_flat_test\;CONFIG_COMPACT_STORAGE CONFIG_ALT_FILE_SEPARATOR\;storage_compact.c"
	)
	foreach(variant IN LISTS profile_provision_variants)
		list(GET variant 0 name)
		list(GET variant 1 defs)
		list(GET variant 2 backend)
		separate_arguments(defs)
		add_executable(${name} profile_provision_test.c
			${PROJECT_SOURCE_DIR}/utils/ss_profile.c
			${PROJECT_SOURCE_DIR}/utils/ss_provision.c
			${PROJECT_SOURCE_DIR}/src/softsim/${backend}
			${PROJECT_SOURCE_DIR}/src/softsim/fs.c
		)
		target_compile_definitions(${name} PRIVATE ${defs})
		target_link_libraries(${name} uicc)
	endforeach()

	# Each variant provisions into its own copy of the template tree, taken at
	# configure time as tests/key_scrub does, so a run rewrites keys in the build
	# directory rather than in the tracked files/. The copy is refreshed before
	# each run, so repeated ctest invocations start from the same tree.
	file(COPY ${CMAKE_SOURCE_DIR}/files DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/pristine)

	foreach(name profile_provision_test profile_provision_compact_test profile_provision_flat_test
		     profile_provision_compact_flat_test)
		set(dir ${CMAKE_CURRENT_BINARY_DIR}/${name}.d)
		file(MAKE_DIRECTORY ${dir})

		add_test(NAME ${name}_setup
			COMMAND sh -c "rm -rf '${dir}/files' '${dir}/flat' && cp -R '${CMAKE_CURRENT_BINARY_DIR}/pristine/files' '${dir}/files'")
		set_tests_properties(${name}_setup PROPERTIES FIXTURES_SETUP ${name}_files)

		add_test(NAME ${name} COMMAND sh -c "$<TARGET_FILE:${name}> > ${dir}/${name}.out")
		set_tests_properties(${name} PROPERTIES
			FIXTURES_REQUIRED ${name}_files
			WORKING_DIRECTORY ${dir})

		add_test(NAME ${name}_compare
			COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol
				${dir}/${name}.out
				${CMAKE_CURRENT_SOURCE_DIR}/profile_provision_test.ok
		)
		set_tests_properties(${name}_compare PROPERTIES DEPENDS ${name})
	endforeach()
endif(TARGET utils)
