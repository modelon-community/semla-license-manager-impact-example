# Copyright (C) 2022 Modelon AB
cmake_minimum_required(VERSION 3.20)
project(sslecho)
add_library(${PROJECT_NAME} STATIC sslecho.c)

if(NOT DEFINED ssl_libs)
    message(FATAL_ERROR "ssl_libs is not defined")
endif()
target_link_libraries(${PROJECT_NAME} license_manager ${ssl_libs} ${extra_ssl_libs})
target_include_directories(${PROJECT_NAME} PRIVATE include)

# copy over .pem files (https://stackoverflow.com/a/17020849)
add_custom_command(
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/cert.pem"
    COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/cert.pem" "${CMAKE_CURRENT_BINARY_DIR}/cert.pem"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/cert.pem"
)
add_custom_command(
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/key.pem"
    COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/key.pem" "${CMAKE_CURRENT_BINARY_DIR}/key.pem"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/key.pem"
)
add_custom_target(pem_files_target 
    DEPENDS
        "${CMAKE_CURRENT_BINARY_DIR}/cert.pem"
        "${CMAKE_CURRENT_BINARY_DIR}/key.pem"
)
add_dependencies(${PROJECT_NAME} pem_files_target)
