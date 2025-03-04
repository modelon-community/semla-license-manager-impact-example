# Generate header files for authorized license servers.
#
# usage: 
# include() this, calls GenPublicKeyJwtH.cmake
# add two lines:
# target_sources(<target> PRIVATE ${PUBLIC_KEY_JWT_H})
# target_include_directories(<target> PRIVATE ${PUBLIC_KEY_JWT_H_INCLUDE_DIR})
# for the '<target>' that needs to include public_key_jwt.h.
#
# required defines:
# PUBLIC_KEY_JWT_H set to for example: ${CMAKE_CURRENT_BINARY_DIR}/public_key_jwt.h
# PUBLIC_KEY_JWT_H_INCLUDE_DIR set to the directory of PUBLIC_KEY_JWT_H, using for example: get_filename_component(PUBLIC_KEY_JWT_H_INCLUDE_DIR ${PUBLIC_KEY_JWT_H} DIRECTORY)
# JWT_PUBLIC_KEYS_DIRECTORY directory of jwt public keys. Must contain a file public_keys_jwt.txt which containst a list of the public keys to use, one public key file per line

if (NOT PUBLIC_KEY_JWT_H)
  message(FATAL_ERROR "PUBLIC_KEY_JWT_H: undefined: set to for example: ${CMAKE_CURRENT_BINARY_DIR}/public_key_jwt.h")
endif()


if (CMAKE_MAJOR_VERSION VERSION_LESS 3)
message(FATAL_ERROR "CMAKE_MAJOR_VERSION=${CMAKE_MAJOR_VERSION}: bracket argument syntax (https://cmake.org/cmake/help/latest/manual/cmake-language.7.html#bracket-argument) is used for quoting in error message in ${CMAKE_CURRENT_LIST_FILE}, which requires cmake version >= 3.0")
endif()
if (NOT PUBLIC_KEY_JWT_H_INCLUDE_DIR)
message(FATAL_ERROR "PUBLIC_KEY_JWT_H_INCLUDE_DIR: undefined: set to the directory of PUBLIC_KEY_JWT_H, using for example: [=[ get_filename_component(PUBLIC_KEY_JWT_H_INCLUDE_DIR ${PUBLIC_KEY_JWT_H} DIRECTORY) ]=]")
endif()
set(PUBLIC_KEY_JWT_LIST ${JWT_PUBLIC_KEYS_DIRECTORY}/public_keys_jwt.txt)
set(PUBLIC_KEY_JWT_KEY_ID_FILE ${JWT_PUBLIC_KEYS_DIRECTORY}/public_keys_jwt_key_id.txt)

if("${JWT_PUBLIC_KEYS_DIRECTORY}" STREQUAL "" OR NOT EXISTS "${PUBLIC_KEY_JWT_LIST}")

message( FATAL_ERROR "\
Error: ${PUBLIC_KEY_JWT_LIST} doesn't exist.
variable JWT_PUBLIC_KEYS_DIRECTORY = ${JWT_PUBLIC_KEYS_DIRECTORY}
passed to CMake as -DJWT_PUBLIC_KEYS_DIRECTORY=public_keys_path

the JWT_PUBLIC_KEYS_DIRECTORY directory must contains:

- the public keys for each of the license servers supported by the generated LVE
to generate a set of keys run the following commands:

openssl genrsa -out \"private_key_path/private_key_tool.pem\" 4096
openssl rsa -pubout -in \"private_key_path/private_key_tool.pem\" -out \"public_keys_path/public_key_jwt.pem\"
dos2unix \"public_keys_path/public_key_jwt.pem\"

- the file 'public_keys_jwt.txt' which containst a list of the public keys to use
one public key file per line

the same set of keys must be used in all builds or the generated LVEs will not be compatible
")
endif()

if(NOT EXISTS "${PUBLIC_KEY_JWT_KEY_ID_FILE}")
message( FATAL_ERROR "\
Error: ${PUBLIC_KEY_JWT_KEY_ID_FILE} doesn't exist.

- the file 'public_keys_jwt_key_id.txt' should contain the Key ID of the key files listed in 'public_keys_jwt.txt'.
one key id per line. The key ID on line 1 corresponds to the key file on line 1 and so on.
")
endif()
file(STRINGS "${PUBLIC_KEY_JWT_LIST}" PUBLIC_KEY_JWT_FILES)
list(LENGTH PUBLIC_KEY_JWT_FILES PUBLIC_KEY_JWT_NUM)

if(NOT PUBLIC_KEY_JWT_NUM)
message( FATAL_ERROR "Error: no public keys in ${PUBLIC_KEY_JWT_LIST}")  
endif()

get_filename_component(PUBLIC_KEY_JWT_H_NAME_WLE ${PUBLIC_KEY_JWT_H} NAME_WLE)

set(OBFUSCATE_COMMAND obfuscate)
set(JWTI 0)
unset(PUBLIC_KEY_JWT_H_FILES)
foreach(KEYFILE ${PUBLIC_KEY_JWT_FILES})
  set(PUBLIC_KEY_JWTI_H "${CMAKE_CURRENT_BINARY_DIR}/${PUBLIC_KEY_JWT_H_NAME_WLE}${JWTI}.h")
	set(PUBLIC_KEY_JWTI_H_COMMAND ${OBFUSCATE_COMMAND} "${PUBLIC_KEY_JWTI_H}" "${JWT_PUBLIC_KEYS_DIRECTORY}/${KEYFILE}" PUBLIC_KEY_JWT${JWTI} TOOL_PUBLIC)
	
  list(APPEND PUBLIC_KEY_JWT_H_FILES "${PUBLIC_KEY_JWTI_H}")
	
  message(STATUS "Adding rule for JWTI=${JWTI} KEYFILE=${JWT_PUBLIC_KEYS_DIRECTORY}/${KEYFILE}")
  add_custom_command(
      OUTPUT "${PUBLIC_KEY_JWTI_H}"
      COMMAND ${PUBLIC_KEY_JWTI_H_COMMAND}
      DEPENDS "${JWT_PUBLIC_KEYS_DIRECTORY}/${KEYFILE}" ${OBFUSCATE_COMMAND}
      COMMENT "Running: ${PUBLIC_KEY_JWTI_H_COMMAND}"
  )
  set_source_files_properties("${PUBLIC_KEY_JWTI_H}" PROPERTIES HEADER_FILE_ONLY TRUE)
  set_source_files_properties("${PUBLIC_KEY_JWTI_H}" PROPERTIES GENERATED 1)
  math(EXPR JWTI ${JWTI}+1)
endforeach()


add_custom_command(
  OUTPUT "${PUBLIC_KEY_JWT_H}"
  COMMAND "${CMAKE_COMMAND}" 
      -D PUBLIC_KEY_JWT_NUM=${PUBLIC_KEY_JWT_NUM} 
      -D PUBLIC_KEY_JWT_H="${PUBLIC_KEY_JWT_H}"
      -D PUBLIC_KEY_JWT_H_NAME_WLE="${PUBLIC_KEY_JWT_H_NAME_WLE}"
      -D PUBLIC_KEY_JWT_KEY_ID_FILE="${PUBLIC_KEY_JWT_KEY_ID_FILE}"
      -P "${CMAKE_CURRENT_LIST_DIR}/GenPublicKeyJwtH.cmake"
  DEPENDS ${OBFUSCATE_COMMAND} "${CMAKE_CURRENT_LIST_DIR}/GenPublicKeyJwtH.cmake" "${PUBLIC_KEY_JWT_LIST}" ${PUBLIC_KEY_JWT_H_FILES}
  )
set_source_files_properties("${PUBLIC_KEY_JWT_H}" PROPERTIES HEADER_FILE_ONLY TRUE)
set_source_files_properties("${PUBLIC_KEY_JWT_H}" PROPERTIES GENERATED 1)
