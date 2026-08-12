add_executable(envelope_test envelope_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(envelope_test uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

# Skip when using external key loading — the default profile OTA packet was
# encrypted with keys stored in files/; the identity stub used for
# CONFIG_EXTERNAL_KEY_LOAD produces different crypto output.
if(NOT CONFIG_EXTERNAL_KEY_LOAD)
    # Snapshot files/ at configure time, as tests/key_scrub and tests/app_transact
    # do: with CONFIG_USE_UTILS the suite's own profile_provision_test rewrites the
    # source tree mid-run (keys in 3f00/a001 and 3f00/a004), so a copy taken while
    # ctest is running can stage a mutated profile.
    file(COPY ${CMAKE_SOURCE_DIR}/files DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/pristine)

    # Refresh from that snapshot before each test run so CNTR writes don't touch
    # the source tree and the test is idempotent across repeated ctest runs.
    add_test(NAME envelope_test_setup
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_CURRENT_BINARY_DIR}/pristine/files
            ${CMAKE_CURRENT_BINARY_DIR}/files
    )
    set_tests_properties(envelope_test_setup PROPERTIES FIXTURES_SETUP envelope_files)

    add_test(NAME envelope_test
        COMMAND sh -c "$<TARGET_FILE:envelope_test> > ${CMAKE_CURRENT_BINARY_DIR}/envelope_test.out 2>&1")
    set_tests_properties(envelope_test PROPERTIES
        FIXTURES_REQUIRED envelope_files
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

    add_test(NAME envelope_test_compare
        COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol
            ${CMAKE_CURRENT_BINARY_DIR}/envelope_test.out
            ${CMAKE_CURRENT_SOURCE_DIR}/envelope_test.ok)
endif()
