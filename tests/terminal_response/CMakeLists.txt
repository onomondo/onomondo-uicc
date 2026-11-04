add_executable(terminal_response_test terminal_response_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(terminal_response_test uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

# The remote write to EF.FPLMN lands in files/, so run on a snapshot taken at
# configure time, as tests/envelope does.
file(COPY ${CMAKE_SOURCE_DIR}/files DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/pristine)

add_test(NAME terminal_response_test_setup
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_BINARY_DIR}/pristine/files
        ${CMAKE_CURRENT_BINARY_DIR}/files
)
set_tests_properties(terminal_response_test_setup PROPERTIES FIXTURES_SETUP terminal_response_files)

add_test(NAME terminal_response_test
    COMMAND sh -c "$<TARGET_FILE:terminal_response_test> > ${CMAKE_CURRENT_BINARY_DIR}/terminal_response_test.out 2>&1")
set_tests_properties(terminal_response_test PROPERTIES
    FIXTURES_REQUIRED terminal_response_files
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_test(NAME terminal_response_test_compare
    COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol
        ${CMAKE_CURRENT_BINARY_DIR}/terminal_response_test.out
        ${CMAKE_CURRENT_SOURCE_DIR}/terminal_response_test.ok)
set_tests_properties(terminal_response_test_compare PROPERTIES DEPENDS terminal_response_test)
