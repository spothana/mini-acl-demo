cmake_minimum_required(VERSION 3.15)

project(mini_acl
        VERSION 1.0.0
        DESCRIPTION "Standalone reimplementation of DPDK ACL concepts"
        LANGUAGES C)

# -- Build settings ---------------------------------------------------------
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

add_compile_options(-Wall -Wextra)

# -- Library ----------------------------------------------------------------
# The core ACL classification engine, reusable by other targets.
add_library(mini_acl STATIC src/mini_acl.c)
target_include_directories(mini_acl PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)

# -- Demo executable --------------------------------------------------------
# Reproduces the DPDK ACL documentation example.
add_executable(acl_demo src/demo.c)
target_link_libraries(acl_demo PRIVATE mini_acl)

# -- Tests ------------------------------------------------------------------
enable_testing()
add_executable(test_acl src/test_acl.c)
target_link_libraries(test_acl PRIVATE mini_acl)
add_test(NAME unit_tests COMMAND test_acl)

# Treat the demo as an integration test: it must run without crashing.
add_test(NAME demo_runs COMMAND acl_demo)

# -- Install ----------------------------------------------------------------
install(TARGETS mini_acl ARCHIVE DESTINATION lib)
install(TARGETS acl_demo RUNTIME DESTINATION bin)
install(FILES include/mini_acl.h DESTINATION include)

# -- Friendly summary -------------------------------------------------------
message(STATUS "mini_acl ${PROJECT_VERSION} -- build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  targets: mini_acl (lib), acl_demo, test_acl")
message(STATUS "  run 'ctest' after building to execute tests")
