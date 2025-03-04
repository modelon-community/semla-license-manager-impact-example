#define _XOPEN_SOURCE 700
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "mfl_common.h"
#ifndef WIN32
#include "mfl_interface.h"
#include "mfl_jwt.h"
#include "unit_test_util.h"
#endif

#ifndef WIN32

static size_t _read_file_from_jwt_key_dir(char **keys_jwt_txt_contents, char **keys_jwt_txt_file_path, char *keys_jwt_txt_file_name)
{
    size_t bytes_read = 0;
    size_t keys_jwt_txt_file_path_sz;
    char *JWT_PUBLIC_KEYS_DIRECTORY = getenv("JWT_PUBLIC_KEYS_DIRECTORY");
    char error_msg_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
    memset(error_msg_buffer, '\0', MFL_JWT_ERROR_MSG_BUFFER_SIZE);
    if (JWT_PUBLIC_KEYS_DIRECTORY == NULL) {
        fprintf(stderr, "environment variable JWT_PUBLIC_KEYS_DIRECTORY not set\n");
        goto error;
    }
    keys_jwt_txt_file_path_sz = strlen(JWT_PUBLIC_KEYS_DIRECTORY) + strlen("/") + strlen(keys_jwt_txt_file_name);
    *keys_jwt_txt_file_path = malloc((keys_jwt_txt_file_path_sz + 1) * sizeof(**keys_jwt_txt_file_path));
    sprintf(*keys_jwt_txt_file_path, "%s%s%s", JWT_PUBLIC_KEYS_DIRECTORY, "/", keys_jwt_txt_file_name);
    FILE *fp = fopen(*keys_jwt_txt_file_path, "r");
    if (fp == NULL) {
        perror(FILE_LINE_STRING);
        goto error;
    }
    bytes_read = mfl_jwt_util_read_file(keys_jwt_txt_contents, fp, error_msg_buffer);
    if (bytes_read == 0 || ferror(fp)) {
        fprintf(stderr, "%s: %s\n", FILE_LINE_STRING, error_msg_buffer);
        goto error;
    }
    if(strchr(*keys_jwt_txt_contents, '\r') != NULL) {
        fprintf(stderr, "%s: %s: contains '\\r'. Line endings need to be a single '\\n', i.e. only Unix line endings are supported. Run dos2unix on the file to convert from windows line endings to unix line endings.\n", FILE_LINE_STRING, *keys_jwt_txt_file_path);
        goto error;
    }
error:
    return bytes_read;
}

static int _read_key_file_from_jwt_key_dir(char **jwt_key_file_path, char *keys_jwt_txt_file_name)
{
    int result = MFL_ERROR;
    char *keys_jwt_txt_contents = NULL;
    char *keys_jwt_txt_file_path = NULL;
    size_t bytes_read;
    bytes_read = _read_file_from_jwt_key_dir(&keys_jwt_txt_contents, &keys_jwt_txt_file_path, keys_jwt_txt_file_name);
    if (bytes_read == 0) {
        goto error;
    }
    // read key file name from line number 'UNIT_TEST_PUBLIC_KEY_JWT_KEY_INDEX' in public_keys_jwt.txt or private_keys_jwt.txt
    char *line_start = keys_jwt_txt_contents;
    char *line_end = NULL;
    int i = 0;
    do {
        line_end = strchr(line_start, '\n');
        if(line_end == NULL) {
            line_end = strchr(line_start, '\0');
            break;
        }

        // update
        i++;
        if (i < UNIT_TEST_PUBLIC_KEY_JWT_KEY_INDEX) {
            line_start = line_end + 1;
        }
    } while (i < UNIT_TEST_PUBLIC_KEY_JWT_KEY_INDEX);
    if(i < UNIT_TEST_PUBLIC_KEY_JWT_KEY_INDEX) {
        fprintf(stderr, "%s:%d: last line of file reached: no newline on the last line of the file is required, however expected number of lines to be at least UNIT_TEST_PUBLIC_KEY_JWT_KEY_INDEX + 1 = %d\n", keys_jwt_txt_file_path, i+1, UNIT_TEST_PUBLIC_KEY_JWT_KEY_INDEX + 1);
        goto error;
    }

    // when the line ends with a '\n', strip the '\n' by overwriting it with '\0'.
    // (when the line ends with a '\0', this overwrites it with the same character)
    *line_end = '\0'; 

    *jwt_key_file_path = strdup(line_start);
    if (*jwt_key_file_path == NULL) {
        perror(FILE_LINE_STRING);
        goto error;
    }
    result = MFL_SUCCESS;
error:
    free(keys_jwt_txt_contents);
    free(keys_jwt_txt_file_path);
    return result;
}

static int _read_key_from_jwt_key_dir(char **jwt_key, size_t *jwt_key_sz, char *keys_jwt_txt_file_name)
{
    int status = MFL_ERROR;
    size_t bytes_read = 0;
    char *jwt_key_file_name = NULL;
    char *jwt_key_file_path = NULL;
    status = _read_key_file_from_jwt_key_dir(&jwt_key_file_name, keys_jwt_txt_file_name);
    if (status != MFL_SUCCESS) {
        fprintf(stderr, "_read_key_file_from_jwt_key_dir() failed\n");
        goto error;
    }
    bytes_read = _read_file_from_jwt_key_dir(jwt_key, &jwt_key_file_path, jwt_key_file_name);
    if (bytes_read == 0) {
        fprintf(stderr, "_read_file_from_jwt_key_dir() failed\n");
        goto error;
    }
    *jwt_key_sz = strlen(*jwt_key);
    status = MFL_SUCCESS;
error:
    free(jwt_key_file_name);
    free(jwt_key_file_path);
    return status;

}

int read_kid_from_public_keys_jwt_key_id_txt_file(char **kid)
{
    return _read_key_file_from_jwt_key_dir(kid, "public_keys_jwt_key_id.txt");
}

int read_jwt_private_key_from_jwt_key_dir(char **jwt_key, size_t *jwt_key_sz)
{
    return _read_key_from_jwt_key_dir(jwt_key, jwt_key_sz, "private_keys_jwt.txt");
}
int read_jwt_public_key_from_jwt_key_dir(char **jwt_key, size_t *jwt_key_sz)
{
    return _read_key_from_jwt_key_dir(jwt_key, jwt_key_sz, "public_keys_jwt.txt");
}
#endif
