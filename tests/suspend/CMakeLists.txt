add_executable(suspend_test suspend_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(suspend_test uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

if(CONFIG_USE_EXPERIMENTAL_SUSPEND_COMMAND)
    add_test(NAME suspend_test COMMAND sh -c "$<TARGET_FILE:suspend_test> > suspend_test.out 2>&1")
    add_test(NAME suspend_test_compare COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol ${CMAKE_CURRENT_BINARY_DIR}/suspend_test.out ${CMAKE_CURRENT_SOURCE_DIR}/suspend_test.ok)
endif()
