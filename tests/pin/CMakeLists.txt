add_executable(pin_test pin_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(pin_test uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

# The test enables and changes PIN1, so it runs on a private copy of the
# filesystem instead of the one in the source tree, refreshed before each
# run so repeated ctest invocations start from the same state.
file(COPY ${CMAKE_SOURCE_DIR}/files DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/pristine)

add_test(NAME pin_test_setup
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_BINARY_DIR}/pristine/files
        ${CMAKE_CURRENT_BINARY_DIR}/files
)
set_tests_properties(pin_test_setup PROPERTIES FIXTURES_SETUP pin_files)

add_test(NAME pin_test COMMAND sh -c "$<TARGET_FILE:pin_test> > ${CMAKE_CURRENT_BINARY_DIR}/pin_test.out 2>&1")
set_tests_properties(pin_test PROPERTIES
    FIXTURES_REQUIRED pin_files
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_test(NAME pin_test_compare COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol ${CMAKE_CURRENT_BINARY_DIR}/pin_test.out ${CMAKE_CURRENT_SOURCE_DIR}/pin_test.ok)
set_tests_properties(pin_test_compare PROPERTIES DEPENDS pin_test)
