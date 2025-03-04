# Copyright (C) 2022 Modelon AB

# Usage: do not call this directly, instead use: IncludeGenPublicKeyJwtH.cmake

#set(CMAKE_VERBOSE_MAKEFILE ON)

# -------------------------------------------------------------------
# This script is used for generation of public_key_jwt.h file.
# -------------------------------------------------------------------

# required defines:
# PUBLIC_KEY_JWT_NUM number of public keys available
# PUBLIC_KEY_JWT_H name of the output file to generate
# PUBLIC_KEY_JWT_H_NAME_WLE set to the filename without longest extension (WLE) of PUBLIC_KEY_JWT_H, using for example: [=[ get_filename_component(PUBLIC_KEY_JWT_H_NAME_WLE ${PUBLIC_KEY_JWT_H} NAME_WLE) ]=]
# PUBLIC_KEY_JWT_KEY_ID_FILE input file with key ids
if (NOT PUBLIC_KEY_JWT_NUM)
  message( FATAL_ERROR "Error: PUBLIC_KEY_JWT_NUM undefined")  
endif()
if (NOT PUBLIC_KEY_JWT_H)
  message( FATAL_ERROR "Error: PUBLIC_KEY_JWT_H undefined")  
endif()

if (CMAKE_MAJOR_VERSION VERSION_LESS 3)
  message(FATAL_ERROR "CMAKE_MAJOR_VERSION=${CMAKE_MAJOR_VERSION}: bracket argument syntax (https://cmake.org/cmake/help/latest/manual/cmake-language.7.html#bracket-argument) is used for quoting in error message in ${CMAKE_CURRENT_LIST_FILE}, which requires cmake version >= 3.0")
endif()
if (NOT PUBLIC_KEY_JWT_H_NAME_WLE)
  message(FATAL_ERROR "PUBLIC_KEY_JWT_H_NAME_WLE: undefined: set to the filename without longest extension (WLE) of PUBLIC_KEY_JWT_H, using for example: [=[ get_filename_component(PUBLIC_KEY_JWT_H_NAME_WLE ${PUBLIC_KEY_JWT_H} NAME_WLE) ]=]")
endif()

message(STATUS "Generating ${PUBLIC_KEY_JWT_H} for ${PUBLIC_KEY_JWT_NUM} keys")
math(EXPR MAXIND ${PUBLIC_KEY_JWT_NUM}-1)
# generate number of keys define
FILE(WRITE "${PUBLIC_KEY_JWT_H}"
"#define PUBLIC_KEY_JWT_NUM ( ${PUBLIC_KEY_JWT_NUM} )
"
)
# generate includes for all keys
foreach(PUBLIC_KEY_JWT_I RANGE ${MAXIND})
  FILE(APPEND "${PUBLIC_KEY_JWT_H}"
"#include \"${PUBLIC_KEY_JWT_H_NAME_WLE}${PUBLIC_KEY_JWT_I}.h\"
"
)
endforeach()

# generate DECLARE_PUBLIC_KEY_JWT()
FILE(APPEND "${PUBLIC_KEY_JWT_H}"
"#define DECLARE_PUBLIC_KEY_JWT()"
)
foreach(PUBLIC_KEY_JWT_I RANGE ${MAXIND})
  FILE(APPEND "${PUBLIC_KEY_JWT_H}" "DECLARE_PUBLIC_KEY_JWT${PUBLIC_KEY_JWT_I}();"
)
endforeach()

FILE(APPEND "${PUBLIC_KEY_JWT_H}" "unsigned char* PUBLIC_KEY_JWT[]={"
)
foreach(PUBLIC_KEY_JWT_I RANGE ${MAXIND})
  FILE(APPEND "${PUBLIC_KEY_JWT_H}" "PUBLIC_KEY_JWT${PUBLIC_KEY_JWT_I},"
)
endforeach()

FILE(APPEND "${PUBLIC_KEY_JWT_H}" 
"0}
")

  
# generate DECLARE_PUBLIC_KEY_JWT_LEN()
FILE(APPEND "${PUBLIC_KEY_JWT_H}"
"#define DECLARE_PUBLIC_KEY_JWT_LEN() size_t PUBLIC_KEY_JWT_LEN[]={"
)
foreach(PUBLIC_KEY_JWT_I RANGE ${MAXIND})
  FILE(APPEND "${PUBLIC_KEY_JWT_H}" "PUBLIC_KEY_JWT${PUBLIC_KEY_JWT_I}_LEN,"
)
endforeach()
FILE(APPEND "${PUBLIC_KEY_JWT_H}" "0}
")

# generate INITIALIZE_PUBLIC_KEY_JWT()
FILE(APPEND "${PUBLIC_KEY_JWT_H}"
"#define INITIALIZE_PUBLIC_KEY_JWT() do {"
)
foreach(PUBLIC_KEY_JWT_I RANGE ${MAXIND})
  FILE(APPEND "${PUBLIC_KEY_JWT_H}" "INITIALIZE_PUBLIC_KEY_JWT${PUBLIC_KEY_JWT_I}();"
)
endforeach()
FILE(APPEND "${PUBLIC_KEY_JWT_H}" "} while (0)
")

# generate CLEAR_PUBLIC_KEY_JWT()
FILE(APPEND "${PUBLIC_KEY_JWT_H}"
"#define CLEAR_PUBLIC_KEY_JWT() do {"
)
foreach(PUBLIC_KEY_JWT_I RANGE ${MAXIND})
  FILE(APPEND "${PUBLIC_KEY_JWT_H}" "CLEAR_PUBLIC_KEY_JWT${PUBLIC_KEY_JWT_I}();"
)
endforeach()
FILE(APPEND "${PUBLIC_KEY_JWT_H}" "} while (0)
")

# generate key id
file(STRINGS "${PUBLIC_KEY_JWT_KEY_ID_FILE}" PUBLIC_KEY_JWT_KEY_ID_LIST)
FILE(APPEND "${PUBLIC_KEY_JWT_H}" "#define DECLARE_PUBLIC_KEY_JWT_KEY_ID() unsigned char* PUBLIC_KEY_JWT_KEY_ID[]={ \\
")
foreach(PUBLIC_KEY_JWT_I RANGE ${MAXIND})
  list(GET PUBLIC_KEY_JWT_KEY_ID_LIST ${PUBLIC_KEY_JWT_I} PUBLIC_KEY_JWT_KEY_ID_LIST_I)
  FILE(APPEND "${PUBLIC_KEY_JWT_H}"
  "    \"${PUBLIC_KEY_JWT_KEY_ID_LIST_I}\" /* PUBLIC_KEY_JWT${PUBLIC_KEY_JWT_I} */, \\
")
endforeach()
FILE(APPEND "${PUBLIC_KEY_JWT_H}" "}
")