
set(CURL_ARCHIVE_URL "file://${CMAKE_SOURCE_DIR}/curl-7_61_1.zip")
set(CURL_ARCHIVE_EXPECTED_HASH_SHA256 "2b1cf218a1090556ad4437acbdca398e1d06bdac3091bc71b8a2a53a8026c776")

message(STATUS "CURL_ARCHIVE_URL=${CURL_ARCHIVE_URL}")
message(STATUS "CURL_ARCHIVE_EXPECTED_HASH_SHA256=${CURL_ARCHIVE_EXPECTED_HASH_SHA256}")


string(REGEX REPLACE ".*/" "" CURL_ARCHIVE_FILENAME ${CURL_ARCHIVE_URL})

# use the 'stem' = the filename without the .zip extension as the destination directory when extracting the archive
string(REGEX REPLACE ".zip$" "" CURL_ARCHIVE_FILENAME_STEM ${CURL_ARCHIVE_FILENAME})
message(STATUS "Will use CURL from ${CURL_ARCHIVE_URL}")


file(DOWNLOAD
    ${CURL_ARCHIVE_URL}
    ${CURL_ARCHIVE_FILENAME}
    EXPECTED_HASH SHA256=${CURL_ARCHIVE_EXPECTED_HASH_SHA256}
    TLS_VERIFY ON
    NETRC OPTIONAL
)
file(ARCHIVE_EXTRACT INPUT ${CURL_ARCHIVE_FILENAME}
    DESTINATION "${CMAKE_BINARY_DIR}/${CURL_ARCHIVE_FILENAME_STEM}"
)

find_library(CURL_LIBRARY 
    NAMES curl curllib libcurl_imp curllib_static libcurl.so.4
    HINTS /usr/lib/x86_64-linux-gnu/ /usr/lib64/
)
MESSAGE(STATUS "libcurl found in ${CURL_LIBRARY}" )

include_directories(${CMAKE_BINARY_DIR}/${CURL_ARCHIVE_FILENAME_STEM}/curl-curl-7_61_1/include/)
