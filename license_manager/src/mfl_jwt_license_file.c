#define _XOPEN_SOURCE 700
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mfl_common.h"
#include "mfl_interface.h"
#include "mfl_jwt.h"
#include "mfl_jwt_license_file.h"
#include "mfl_jwt_license_file_decrypt_file.h"

#define STR2(x) #x
#define STR(x) STR2(x)

static int mfl_jwt_license_file_get_decrypted_license_file_contents(
    char **decrypted_license_file_contents, char *libpath,
    char *error_msg_buffer)
{
    int result = MFL_ERROR;
    int status = MFL_ERROR;
    FILE *fp = NULL;
    char *license_file_relative_path = NULL;
    char *license_file_path = NULL;
    size_t bytes_read = 0;
    char *encrypted_license_file_contents = NULL;

    // license file has the file extension .mo when it is not encrypted and
    // has the file extension .moc after it is encrypted by packagetool
    status =
        mfl_jwt_util_asprintf(error_msg_buffer, &license_file_relative_path,
                              "%sc", STR(MFL_JWT_LICENSE_FILE_FILENAME));
    if (status != MFL_SUCCESS) {
        result = status;
        goto error;
    }
    status =
        mfl_jwt_util_asprintf(error_msg_buffer, &license_file_path, "%s/%s",
                              libpath, license_file_relative_path);
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
        error_msg_buffer, libpath, license_file_relative_path,
        encrypted_license_file_contents, bytes_read,
        decrypted_license_file_contents);
    if (status != MFL_SUCCESS) {
        result = status;
        goto error;
    }

    result = MFL_SUCCESS;
error:
    if (fp != NULL) {
        fclose(fp);
    }
    free(license_file_relative_path);
    free(encrypted_license_file_contents);
    free(license_file_path);
    return result;
}

/** Populates required_usernames from decrypted_license_file_contents.
 *
 * All lines that contain a '@' are considered a username.
 * Filters out all lines that are not usernames.
 * Ensures that the only separator between usernames is '\n'
 * (i.e. replaces Windows and Mac line endings with Unix line endings)
 *
 * @param required_usernames contains the required users from the license file
 * separated by '\n'
 * @param decrypted_license_file_contents contains the decrypted license file
 * contents
 * @return MFL_SUCCESS on success, or MFL_ERROR on failure. required_usernames.
 * Caller must free() required_usernames.
 */
static int
mfl_jwt_license_file_filter_out_required_usernames_from_decrypted_license_file_contents(
    char **required_usernames, char *decrypted_license_file_contents,
    char *error_msg_buffer)
{
    int result = MFL_ERROR;
    int status = MFL_ERROR;
    size_t required_usernames_sz = 0;
    size_t required_usernames_capacity = 8192;
    char *line_start = decrypted_license_file_contents;
    char *line_end = NULL;
    char *at_sign = NULL;
    size_t bytes_read = -1;
    char *required_usernames_p = NULL;
    char *line_end_in_required_usernames = NULL;

    *required_usernames = (char *)malloc(required_usernames_capacity *
                                         sizeof(**required_usernames));
    if (*required_usernames == NULL) {
        snprintf(error_msg_buffer, MFL_JWT_ERROR_MSG_BUFFER_SIZE,
                 "error: Could not allocate "
                 "memory for output buffer required_usernames");
        result = MFL_ERROR;
        goto error;
    }

    required_usernames_p = *required_usernames;
    do {
        // Only copy lines that contain a '@'
        if (at_sign < line_start) {
            at_sign = strchr(line_start, '@');
            if (at_sign == NULL) {
                // If there are no more lines with a '@' left,
                // then we are done.
                break;
            }
        }

        // Find the line ending
        line_end = strchr(line_start, '\r');
        if (line_end == NULL) {
            line_end = strchr(line_start, '\n');
            if (line_end == NULL) {
                line_end = strchr(line_start, '\0');
            }
        } else {
            // this happens when there's a Unix line ending before a Windows line ending
            char *line_end2 = strchr(line_start, '\n');
            if (line_end2 != NULL) {
                if (line_end2 < line_end) {
                    line_end = line_end2;
                }
            }
        }

        // Copy the line if it contains a '@'
        if (at_sign < line_end) {
            // bytes_read also includes the line ending itself
            bytes_read = line_end - line_start + 1;
            required_usernames_sz += bytes_read;
            // Reallocate output buffer if it is too small
            if (required_usernames_sz >= required_usernames_capacity) {
                required_usernames_capacity = required_usernames_capacity * 2;
                *required_usernames = (char *)realloc(
                    *required_usernames,
                    required_usernames_capacity * sizeof(**required_usernames));
                if (*required_usernames == NULL) {
                    snprintf(error_msg_buffer, MFL_JWT_ERROR_MSG_BUFFER_SIZE,
                             "error: Could not allocate "
                             "memory for output buffer required_usernames");
                    goto error;
                }
                required_usernames_p =
                    *required_usernames + (required_usernames_sz - bytes_read);
            }
            memcpy(required_usernames_p, line_start, bytes_read);
            // (bytes_read also includes the line ending itself)
            line_end_in_required_usernames =
                required_usernames_p + bytes_read - 1;
            // Fix the line endings in the output buffer, we only want to output
            // Unix line endings (\n)
            if (*line_end == '\r') {
                char *line_end_plus_one = line_end + 1;
                // replace Windows (\r\n) and Mac (\r) line endings with Unix
                // line endings (\n)
                *line_end_in_required_usernames = '\n';
                // fast-forward the input buffer pointer to the '\n' in Windows
                // line endings
                if (*line_end_plus_one == '\n') {
                    line_end = line_end_plus_one;
                }
            }
            required_usernames_p = line_end_in_required_usernames + 1;
        }
        line_start = line_end + 1;
    } while (*line_end != '\0');
    if (required_usernames_sz >= 1) {
        // Here, we ensure that the final line ending is always '\0'.
        // we include the line endings when we copy,
        // but the output should only be *separated* by
        // '\n' (not also end with a '\n').
        // Example: "a\nb\n" -> "a\nb"
        (*required_usernames)[required_usernames_sz - 1] = '\0';
    } else {
        // Here, required_usernames_sz == 0, this ensures that what is output is
        // always a null-terminated string.
        (*required_usernames)[required_usernames_sz] = '\0';
    }

    result = MFL_SUCCESS;
error:
    return result;
}

int mfl_jwt_license_file_get_required_usernames(char **required_usernames,
                                                char *libpath,
                                                char *error_msg_buffer)
{
    int result = MFL_ERROR;
    int status = MFL_ERROR;
    char *decrypted_license_file_contents = NULL;

    status = mfl_jwt_license_file_get_decrypted_license_file_contents(
        &decrypted_license_file_contents, libpath, error_msg_buffer);
    if (status != MFL_SUCCESS) {
        result = status;
        goto error;
    }
    assert(decrypted_license_file_contents !=
           NULL); // silence warning about null pointer
    status =
        mfl_jwt_license_file_filter_out_required_usernames_from_decrypted_license_file_contents(
            required_usernames, decrypted_license_file_contents,
            error_msg_buffer);
    if (status != MFL_SUCCESS) {
        result = status;
        goto error;
    }

    result = MFL_SUCCESS;
error:
    free(decrypted_license_file_contents);
    return result;
}
