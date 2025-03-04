cmake_minimum_required(VERSION 3.20 FATAL_ERROR) # using cmake_path() which is only available since CMake version 3.20 

# License manager common code
set(LICENSE_MANAGER_COMMON_SRC   "${CMAKE_CURRENT_LIST_DIR}/../common_src")

include_directories(${CMAKE_CURRENT_LIST_DIR})
include_directories(${LICENSE_MANAGER_COMMON_SRC})

add_library(license_manager
    ${CMAKE_CURRENT_LIST_DIR}/lve_license_impact.c
    ${CMAKE_CURRENT_LIST_DIR}/mfl_interface.c
    ${CMAKE_CURRENT_LIST_DIR}/mfl_jwt.c
    ${CMAKE_CURRENT_LIST_DIR}/mfl_jwt_curl.c
    ${CMAKE_CURRENT_LIST_DIR}/mfl_jwt_license_file.c
    ${CMAKE_CURRENT_LIST_DIR}/mfl_jwt_license_file_decrypt_file.c
    ${CMAKE_CURRENT_LIST_DIR}/mfl_jwt_util.c
    ${LICENSE_MANAGER_COMMON_SRC}/lmc_feature.c
)

if (NOT MFL_JWT_LICENSE_FILE_FILENAME)
    message(FATAL_ERROR "error: variable not set: MFL_JWT_LICENSE_FILE_FILENAME")
endif()
target_compile_definitions(license_manager PRIVATE MFL_JWT_LICENSE_FILE_FILENAME=${MFL_JWT_LICENSE_FILE_FILENAME})

include(${CMAKE_CURRENT_LIST_DIR}/../jansson/CMakeLists.txt)
include(${CMAKE_CURRENT_LIST_DIR}/../libjwt/CMakeLists.txt)
include(${CMAKE_CURRENT_LIST_DIR}/../public_key_jwt/CMakeLists.txt)

target_link_libraries(license_manager jwt jansson ${ssl_libs} ${extra_ssl_libs})

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../tests ${CMAKE_CURRENT_BINARY_DIR}/tests)