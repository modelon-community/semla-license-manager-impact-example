#define _XOPEN_SOURCE 700
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mfl_common.h"
#include "mfl_interface.h"
#include "mfl_jwt.h"
#include "mfl_jwt_license_file.h"
#include "mfl_jwt_license_file_decrypt_file.h"
#include "mfl_jwt_util.h"

#define STR2(x) #x
#define STR(x) STR2(x)

static int mfl_jwt_license_file_get_decrypted_license_file_contents(
    char **decrypted_license_file_contents, char *error_msg_buffer)
{
    int result = MFL_ERROR;
    int status = MFL_ERROR;
    FILE *fp = NULL;
    char *license_file_path = NULL;
    char *HOME = NULL;
    size_t bytes_read = 0;
    char *encrypted_license_file_contents = NULL;

    HOME = getenv("HOME");
    if (HOME == NULL) {
        result = MFL_ERROR;
        snprintf(error_msg_buffer, MFL_JWT_ERROR_MSG_BUFFER_SIZE,
                 "error: could not open license file '${HOME}/%s': environment "
                 "variable HOME is not set",
                 STR(MFL_JWT_LICENSE_FILE_FILENAME));
        goto error;
    }
    status =
        mfl_jwt_util_asprintf(error_msg_buffer, &license_file_path, "%s/%s",
                              HOME, STR(MFL_JWT_LICENSE_FILE_FILENAME));
    if (status != MFL_SUCCESS) {
        result = status;
        goto error;
    }
    fp = fopen(license_file_path, "r");
    if (fp == NULL) {
        snprintf(error_msg_buffer, MFL_JWT_ERROR_MSG_BUFFER_SIZE,
                 "error: could not open license file '%s': %s",
                 license_file_path, strerror(errno));
        result = MFL_ERROR;
        goto error;
    }
    bytes_read = mfl_jwt_util_read_file(&encrypted_license_file_contents, fp,
                                        error_msg_buffer);
    if (bytes_read == 0 || ferror(fp)) {
        snprintf(error_msg_buffer, MFL_JWT_ERROR_MSG_BUFFER_SIZE,
                 "error: could open but not read from license file '%s'",
                 license_file_path);
        result = MFL_ERROR;
        goto error;
    }

    status = mfl_jwt_license_file_decrypt_file(
        error_msg_buffer, license_file_path, encrypted_license_file_contents,
        bytes_read, decrypted_license_file_contents);
    if (status != MFL_SUCCESS) {
        result = status;
        goto error;
    }

    result = MFL_SUCCESS;
error:
    free(encrypted_license_file_contents);
    free(license_file_path);
    return result;
}

int mfl_jwt_license_file_get_required_user(char **required_user,
                                           char *error_msg_buffer)
{
    int result = MFL_ERROR;
    int status = MFL_ERROR;

    // license file only contains required_user (for now) so we pass this in as
    // the output buffer directly
    status = mfl_jwt_license_file_get_decrypted_license_file_contents(
        required_user, error_msg_buffer);
    if (status != MFL_SUCCESS) {
        result = status;
        goto error;
    }

    result = MFL_SUCCESS;
error:
    return result;
}
