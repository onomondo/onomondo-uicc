add_executable(refresh_test refresh_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(refresh_test uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

# The test relaxes the TAR record in its own copy of files/, taken at configure
# time as tests/envelope does, and refreshed before every run.
file(COPY ${CMAKE_SOURCE_DIR}/files DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/pristine)

add_test(NAME refresh_test_setup
	COMMAND ${CMAKE_COMMAND} -E copy_directory
		${CMAKE_CURRENT_BINARY_DIR}/pristine/files
		${CMAKE_CURRENT_BINARY_DIR}/files
)
set_tests_properties(refresh_test_setup PROPERTIES FIXTURES_SETUP refresh_files)

add_test(NAME refresh_test
	COMMAND sh -c "$<TARGET_FILE:refresh_test> > ${CMAKE_CURRENT_BINARY_DIR}/refresh_test.out 2>&1")
set_tests_properties(refresh_test PROPERTIES
	FIXTURES_REQUIRED refresh_files
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_test(NAME refresh_test_compare
	COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol
		${CMAKE_CURRENT_BINARY_DIR}/refresh_test.out
		${CMAKE_CURRENT_SOURCE_DIR}/refresh_test.ok)
set_tests_properties(refresh_test_compare PROPERTIES DEPENDS refresh_test)
