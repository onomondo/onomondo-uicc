# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

# libFuzzer targets. Enabled with -DCONFIG_BUILD_FUZZERS=y (clang only).
#
# Each binary serves two purposes:
#   ctest   `<target> <corpus> -runs=0` replays the seed corpus and exits. It is
#           deterministic and sub-second, so it runs on every PR and turns a
#           fixed crash into a permanent regression test.
#   CI job  `<target> <corpus> -max_total_time=N` does the actual searching, and
#           is gated to release branches, manual dispatch and the weekly cron.
#           See the `fuzz` job in .github/workflows/ci_uicc.yml.

find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(corpus_dir ${CMAKE_CURRENT_BINARY_DIR}/corpus)

add_custom_command(
	OUTPUT ${corpus_dir}/.stamp
	COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/gen_corpus.py
			--init-test ${PROJECT_SOURCE_DIR}/tests/init/init_test.c
			--out ${corpus_dir}
	COMMAND ${CMAKE_COMMAND} -E touch ${corpus_dir}/.stamp
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/gen_corpus.py
			${PROJECT_SOURCE_DIR}/tests/init/init_test.c
	COMMENT "Generating fuzz seed corpus"
	VERBATIM
)
add_custom_target(fuzz_corpus DEPENDS ${corpus_dir}/.stamp)

# -fsanitize=fuzzer is added per target; the coverage instrumentation the
# fuzzer feeds on is applied tree-wide by the top-level CMakeLists.
function(add_fuzz_target name source corpus)
	add_executable(${name} ${source})
	target_include_directories(${name} PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include)
	target_compile_options(${name} PRIVATE -fsanitize=fuzzer)
	target_link_options(${name} PRIVATE -fsanitize=fuzzer)
	add_dependencies(${name} fuzz_corpus)

	add_test(NAME ${name}_corpus COMMAND ${name} ${corpus_dir}/${corpus} -runs=0)
endfunction()

# ss_transact() and ss_application_apdu_transact() share a signature but not a
# parser, so the same harness covers both.
foreach(entry IN ITEMS ss_transact ss_application_apdu_transact)
	if(entry STREQUAL "ss_transact")
		set(target fuzz_apdu_t0)
	else()
		set(target fuzz_apdu_app)
	endif()

	add_fuzz_target(${target} fuzz_apdu.c apdu)
	target_compile_definitions(${target} PRIVATE
		FUZZ_ENTRY=${entry}
		SS_FUZZ_FILES_SRC="${PROJECT_SOURCE_DIR}/files"
	)
	# Order matters: these are plain static archives with no declared
	# interdependencies, and milenage pulls aes_128_encrypt_block out of
	# crypto. Same order as tests/init.
	target_link_libraries(${target} PRIVATE uicc milenage crypto storage)
endforeach()

# The profile parser lives in the utils library, which is optional.
if(TARGET utils)
	add_fuzz_target(fuzz_profile fuzz_profile.c profile)
	target_link_libraries(fuzz_profile PRIVATE utils uicc)
else()
	message(STATUS "Fuzz: skipping fuzz_profile (needs -DCONFIG_USE_UTILS=y)")
endif()
