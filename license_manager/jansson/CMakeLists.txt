# Copyright (C) 2022 Modelon AB

set(JANSSON_ARCHIVE_URL "file://${CMAKE_SOURCE_DIR}/jansson-1.0.4.zip")
set(JANSSON_ARCHIVE_EXPECTED_HASH_SHA256 "a7ee91d9e7823c63738a4fbc8e17fd6572bbd5beab536db762df26994d5b9599")

message(STATUS "JANSSON_ARCHIVE_URL=${JANSSON_ARCHIVE_URL}")
message(STATUS "JANSSON_ARCHIVE_EXPECTED_HASH_SHA256=${JANSSON_ARCHIVE_EXPECTED_HASH_SHA256}")


string(REGEX REPLACE ".*/" "" JANSSON_ARCHIVE_FILENAME ${JANSSON_ARCHIVE_URL})

# use the 'stem' = the filename without the .zip extension as the destination directory when extracting the archive
string(REGEX REPLACE ".zip$" "" JANSSON_ARCHIVE_FILENAME_STEM ${JANSSON_ARCHIVE_FILENAME})
message(STATUS "Will use JANSSON from ${JANSSON_ARCHIVE_URL}")


file(DOWNLOAD
    ${JANSSON_ARCHIVE_URL}
    ${JANSSON_ARCHIVE_FILENAME}
    EXPECTED_HASH SHA256=${JANSSON_ARCHIVE_EXPECTED_HASH_SHA256}
    TLS_VERIFY ON
    NETRC OPTIONAL
)
file(ARCHIVE_EXTRACT INPUT ${JANSSON_ARCHIVE_FILENAME}
    DESTINATION "${CMAKE_BINARY_DIR}/${JANSSON_ARCHIVE_FILENAME_STEM}"
)
add_library(jansson STATIC IMPORTED)
set_target_properties(jansson PROPERTIES IMPORTED_LOCATION ${CMAKE_BINARY_DIR}/${JANSSON_ARCHIVE_FILENAME_STEM}/${JANSSON_ARCHIVE_FILENAME_STEM}/usr/local/lib/${CMAKE_STATIC_LIBRARY_PREFIX}jansson${CMAKE_STATIC_LIBRARY_SUFFIX})
include_directories(${CMAKE_BINARY_DIR}/${JANSSON_ARCHIVE_FILENAME_STEM}/${JANSSON_ARCHIVE_FILENAME_STEM}/usr/local/include)

