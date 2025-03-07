cmake_minimum_required (VERSION 3.20 FATAL_ERROR)

# project(MFL_TESTS C)

include(ExternalProject)
include(CheckTypeSize)

include_directories(${CMAKE_CURRENT_LIST_DIR}/include)

add_library(unit_test_util OBJECT unit_test_util.c)
target_link_libraries(unit_test_util license_manager)

if(SKIP_SEMLA_SRC_TESTS)
    message (STATUS "Skipping build of test_mfl_license_check as SKIP_SEMLA_SRC_TESTS is set")
else()
    include_directories(${CMAKE_CURRENT_LIST_DIR}/../include)
    add_executable(test_mfl_license_check
        test_mfl_license_check.c
        $<TARGET_OBJECTS:unit_test_util>
    )

    if (NOT MFL_JWT_LICENSE_FILE_FILENAME)
        message(FATAL_ERROR "error: variable not set: MFL_JWT_LICENSE_FILE_FILENAME")
    endif()
    target_compile_definitions(test_mfl_license_check PRIVATE MFL_JWT_LICENSE_FILE_FILENAME=${MFL_JWT_LICENSE_FILE_FILENAME})

    target_link_libraries(test_mfl_license_check license_manager)
    add_subdirectory(sslecho)
    target_link_libraries(test_mfl_license_check sslecho)
    target_include_directories(test_mfl_license_check PRIVATE sslecho/include)

    target_link_libraries(test_mfl_license_check check dl pthread rt m)

    if (NOT WIN32)
        add_executable(mfl_test_gen_public_key_jwt_h
            mfl_test_gen_public_key_jwt_h.c
            $<TARGET_OBJECTS:unit_test_util>
        )
        target_link_libraries(mfl_test_gen_public_key_jwt_h license_manager)
    endif()

    if (NOT WIN32)
        # add the toplevel public_key_jwt.h file to test_mfl_license_check, used for constructing a valid JWT with a kid that exists in license_manager
        # also add it to mfl_test_gen_public_key_jwt_h
        set(PUBLIC_KEY_JWT_H "${CMAKE_CURRENT_BINARY_DIR}/../public_key_jwt.h")
        get_filename_component(PUBLIC_KEY_JWT_H_INCLUDE_DIR ${PUBLIC_KEY_JWT_H} DIRECTORY)
        # In order for cmake to pass the configure stage without getting an error:
        #
        # CMake Error at tests/CMakeLists.txt:21 (add_executable):
        #  Cannot find source file:
        #
        #  /workspaces/semla-license-manager-impact-example/build/license_managers/license_manager/public_key_jwt.h
        # 
        # removed the line:  target_sources(test_mfl_license_check PRIVATE ${PUBLIC_KEY_JWT_H})
        target_include_directories(test_mfl_license_check PRIVATE ${PUBLIC_KEY_JWT_H_INCLUDE_DIR})
        target_include_directories(mfl_test_gen_public_key_jwt_h PRIVATE ${PUBLIC_KEY_JWT_H_INCLUDE_DIR})
        unset(PUBLIC_KEY_JWT_H)
        unset(PUBLIC_KEY_JWT_H_INCLUDE_DIR)
    endif()

    ##############################################################################
    # TEST
    ##############################################################################
    add_test(NAME test_mfl_license_check COMMAND test_mfl_license_check)
    add_test(NAME mfl_test_gen_public_key_jwt_h COMMAND mfl_test_gen_public_key_jwt_h)
endif()
