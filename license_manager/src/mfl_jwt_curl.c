#define _XOPEN_SOURCE 700
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mfl_common.h"
#include "mfl_interface.h"
#include "mfl_jwt.h"
#include "mfl_jwt_util.h"
#include "mfl_jwt_curl.h"


int mfl_jwt_url_http_and_https(char **jwt_token, char *error_msg_buffer)
{
    int result = MFL_ERROR;
    int status = MFL_ERROR;
    char *url;
    const char *MFL_SSL_NO_VERIFY = getenv("MFL_SSL_NO_VERIFY");
    long timeout;
    char *curl_command = NULL;
    int bytes_read;

    char *curl_option_insecure =
        /* do not verify the server's SSL certificate if the environment
           variable MFL_SSL_NO_VERIFY is set. workaround for using self-signed
           certificates without loading them into curl. using this when testing
           https url by setting the variable MFL_SSL_NO_VERIFY=1
           */
        (MFL_SSL_NO_VERIFY != NULL && strcmp(MFL_SSL_NO_VERIFY, "1") == 0)
            ? "--insecure"
            : "";

    mfl_jwt_ssl_util_get_timeout(&timeout, error_msg_buffer);

    url = getenv("MODELON_LICENSE_USER_JWT_URL");
    if (url == NULL) {
        _print_to_error_msg_buffer(
            error_msg_buffer,
            "error: environment variable not set: MODELON_LICENSE_USER_JWT_URL");
        goto error;
    }

    status = mfl_jwt_util_asprintf(
        error_msg_buffer, &curl_command,
        "curl --silent --show-error --max-time %d %s --url \"%s\"", timeout,
        curl_option_insecure, url);
    if (status != MFL_SUCCESS) {
        result = status;
        goto error;
    }

    bytes_read = mfl_jwt_util_popen(curl_command, jwt_token, error_msg_buffer);

    if (bytes_read == 0) {
        snprintf(error_msg_buffer, MFL_JWT_ERROR_MSG_BUFFER_SIZE,
                 "error: curl command stdout returned no output. curl_command: '%s'", curl_command);
        result = MFL_ERROR;
        goto error;
    } else if (bytes_read < 0) {
        result = MFL_ERROR;
        goto error;
    }

    result = MFL_SUCCESS;
error:
    free(curl_command);
    return result;
}

int mfl_jwt_ssl_util_get_timeout(long *timeout, char *error_msg_buffer)
{
    *timeout = MODELON_LICENSE_USER_JWT_URL_CONNECTION_TIMEOUT_DEFAULT;
    long timeout_from_env;
    const char *MODELON_LICENSE_USER_JWT_URL_CONNECTION_TIMEOUT =
        getenv("MODELON_LICENSE_USER_JWT_URL_CONNECTION_TIMEOUT");
    char *endptr;
    if (MODELON_LICENSE_USER_JWT_URL_CONNECTION_TIMEOUT != NULL) {
        errno = 0;
        timeout_from_env =
            strtol(MODELON_LICENSE_USER_JWT_URL_CONNECTION_TIMEOUT, &endptr, 10);
        if (errno || endptr == MODELON_LICENSE_USER_JWT_URL_CONNECTION_TIMEOUT ||
            *endptr != '\0') {
            snprintf(error_msg_buffer, MFL_JWT_ERROR_MSG_BUFFER_SIZE,
                     "warning: environment variable value could not be parsed: "
                     "MODELON_LICENSE_USER_JWT_URL_CONNECTION_TIMEOUT=%s: "
                     "using default connection timeout (in seconds) "
                     "MODELON_LICENSE_USER_JWT_URL_CONNECTION_TIMEOUT_DEFAULT=%ld\n",
                     MODELON_LICENSE_USER_JWT_URL_CONNECTION_TIMEOUT, *timeout);
            LOGE("%s\n", error_msg_buffer);
            return MFL_ERROR;
        } else {
            *timeout = timeout_from_env;
        }
    }
error:
    return MFL_SUCCESS;
}