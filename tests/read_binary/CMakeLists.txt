add_executable(read_binary_test read_binary_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(read_binary_test uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

# The test grows its copy of EF.ICCID, so it runs on a private copy of the
# filesystem instead of the one in the source tree.
file(COPY ${CMAKE_SOURCE_DIR}/files DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

add_test(NAME read_binary_test COMMAND sh -c "$<TARGET_FILE:read_binary_test> > ${CMAKE_CURRENT_BINARY_DIR}/read_binary_test.out 2>&1")
set_tests_properties(read_binary_test PROPERTIES WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
add_test(NAME read_binary_test_compare COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol ${CMAKE_CURRENT_BINARY_DIR}/read_binary_test.out ${CMAKE_CURRENT_SOURCE_DIR}/read_binary_test.ok)
