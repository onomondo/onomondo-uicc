add_executable(pin_test pin_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(pin_test uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

add_test(NAME pin_test COMMAND sh -c "$<TARGET_FILE:pin_test> > ${CMAKE_CURRENT_BINARY_DIR}/pin_test.out 2>&1")
set_tests_properties(pin_test PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
add_test(NAME pin_test_compare COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol ${CMAKE_CURRENT_BINARY_DIR}/pin_test.out ${CMAKE_CURRENT_SOURCE_DIR}/pin_test.ok)
