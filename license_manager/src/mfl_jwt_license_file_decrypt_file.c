
/* libcrypto-compat.h must be first */
#include "libcrypto-compat.h"

#define _XOPEN_SOURCE 700
#include <errno.h>
#include <libgen.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "mlle_cr_decrypt.h"

#include "mfl_common.h"
#include "mfl_interface.h"
#include "mfl_jwt.h"

int mfl_jwt_license_file_decrypt_file(char *error_msg_buffer, char *libpath,
                                      char *license_file_relative_path,
                                      char *encrypted_license_file_contents,
                                      size_t encrypted_license_file_contents_sz,
                                      char **decrypted_license_file_contents)
{
    /* This function is derived from SEMLA decrypt_file.c */

    int result = MFL_ERROR;
    int bytes = -1;
    mlle_cr_context *context;

    // Allocate output buffer. Output buffer is always shorter than input buffer
    // (see documentation of mlle_cr_decrypt()).
    *decrypted_license_file_contents =
        malloc(encrypted_license_file_contents_sz);
    if (*decrypted_license_file_contents == NULL) {
        snprintf(error_msg_buffer, MFL_JWT_ERROR_MSG_BUFFER_SIZE,
                 "error: when decrypting license file '%s': Could not allocate "
                 "memory for output buffer",
                 license_file_relative_path);
        result = MFL_ERROR;
        goto error;
    }

    context = mlle_cr_create(libpath);
    if (context == NULL) {
        snprintf(error_msg_buffer, MFL_JWT_ERROR_MSG_BUFFER_SIZE,
                 "error: when decrypting license file '%s': Could not create "
                 "decryption context object",
                 license_file_relative_path);
        result = MFL_ERROR;
        goto error2;
    }

    /* OpenSSL initialization stuff. */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    /* Decrypt file. */
    bytes = mlle_cr_decrypt(
        context, license_file_relative_path, encrypted_license_file_contents,
        encrypted_license_file_contents_sz, *decrypted_license_file_contents);
    if (bytes < 0) {
        snprintf(error_msg_buffer, MFL_JWT_ERROR_MSG_BUFFER_SIZE,
                 "error: decryption failed for file: '%s'",
                 license_file_relative_path);
        result = MFL_ERROR;
        goto error3;
    }

    result = MFL_SUCCESS;
error3:
    /* OpenSSL cleanup stuff. */
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
error2:
    mlle_cr_free(context);
error:
    return result;
}
