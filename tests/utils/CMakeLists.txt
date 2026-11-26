# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

ss_add_test(utils_test LIBS uicc)

if(TARGET utils)
	# Test of general utils functions, different from uicc helper functions
	ss_add_test(profile_decode_test LIBS uicc utils)

	# Profile provisioning, one source run against every storage layout: hex or
	# compact (binary) EFs, in a directory tree or flat with the '_' file
	# separator. Every variant prints the same output and is compared against
	# profile_provision_test.ok. Each runs on its own copy of files/, so a run
	# rewrites keys in the build directory rather than in the tracked tree.
	#
	# The default variant links the utils and storage libraries as this
	# configuration builds them. The others compile the profile utils and the
	# storage backend in directly, with their own definitions, as
	# tests/storage_compact does, since the libraries are built for one layout.
	ss_add_test(profile_provision_test FILES LIBS uicc utils storage)

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
		ss_add_test(${name} FILES MAIN profile_provision_test LIBS uicc SOURCES
			${PROJECT_SOURCE_DIR}/utils/ss_profile.c
			${PROJECT_SOURCE_DIR}/utils/ss_provision.c
			${PROJECT_SOURCE_DIR}/src/softsim/${backend}
			${PROJECT_SOURCE_DIR}/src/softsim/fs.c
		)
		target_compile_definitions(${name} PRIVATE ${defs})
	endforeach()
endif(TARGET utils)
