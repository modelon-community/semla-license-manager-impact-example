# Copyright (C) 2022 Modelon AB
if (NOT JWT_PUBLIC_KEYS_DIRECTORY)
    message(FATAL_ERROR "JWT_PUBLIC_KEYS_DIRECTORY is not set")
endif()

# generate ${CMAKE_CURRENT_BINARY_DIR}/public_key_jwt.h
set(PUBLIC_KEY_JWT_H "${CMAKE_CURRENT_BINARY_DIR}/public_key_jwt.h")
get_filename_component(PUBLIC_KEY_JWT_H_INCLUDE_DIR ${PUBLIC_KEY_JWT_H} DIRECTORY)
message(STATUS "Adding rule for ${PUBLIC_KEY_JWT_H}")
include(${CMAKE_CURRENT_LIST_DIR}/IncludeGenPublicKeyJwtH.cmake INCLUDEGENPUBLICKEYH_FOUND)
target_include_directories(license_manager PRIVATE ${PUBLIC_KEY_JWT_H_INCLUDE_DIR})
target_sources(license_manager PRIVATE ${PUBLIC_KEY_JWT_H})
unset(PUBLIC_KEY_JWT_H)
unset(PUBLIC_KEY_JWT_H_INCLUDE_DIR)

# custom target to update JWT Keys from wellknown
add_custom_target(update_jwt_keys_from_wellknown
)
