#define _XOPEN_SOURCE 700
#define _GNU_SOURCE
#include <errno.h>
#include <jansson.h>
#include <jwt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "mfl_common.h"
#include "mfl_interface.h"
#include "mfl_jwt.h"
#include "mfl_jwt_curl.h"
#include "mfl_jwt_license_file.h"
#include "public_key_jwt.h"

struct mfl_license_jwt {
    char *error_msg;
    char *required_usernames;
};

// pre-definitions
static int mfl_jwt_url_file(char **jwt_token, char *error_msg_buffer);

static void set_error(mfl_license_jwt_t *mfl, char *error)
{
    if (mfl->error_msg) {
        free(mfl->error_msg);
    }

    mfl->error_msg = strdup(error);
}

mfl_license_jwt_t *mfl_jwt_license_new()
{
    mfl_license_jwt_t *mfl_license =
        (mfl_license_jwt_t *)calloc(1, sizeof(mfl_license_jwt_t));
    return mfl_license;
}


static int mfl_jwt_initialize_required_usernames(mfl_license_jwt_t *mfl, char *libpath, char *error_msg_buffer)
{
    int result = MFL_ERROR;
    int status = MFL_ERROR;

    status = mfl_jwt_license_file_get_required_usernames(&(mfl->required_usernames), libpath,
                                                    error_msg_buffer);
    if (status != MFL_SUCCESS) {
        result = status;
        goto error;
    }

    result = MFL_SUCCESS;
error:
    return result;
}


int mfl_jwt_initialize(mfl_module_data_t *module_data, char *libpath)
{ 
    mfl_license_jwt_t *mfl = (mfl_license_jwt_t *)module_data;
    int result = MFL_ERROR;
    int status = MFL_ERROR;
    char error_msg_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
    memset(error_msg_buffer, '\0', MFL_JWT_ERROR_MSG_BUFFER_SIZE);
    if (mfl == NULL) {
        return MFL_ERROR;
    }
    status = mfl_jwt_initialize_required_usernames(mfl, libpath, error_msg_buffer);
    if (status != MFL_SUCCESS) {
        set_error(mfl, error_msg_buffer);
        result = status;
        goto error;
    }
    result = MFL_SUCCESS;
error:
    return result;
}

void mfl_jwt_license_free(mfl_module_data_t *module_data)
{
    mfl_license_jwt_t *mfl = (mfl_license_jwt_t *)module_data;
    free(mfl);
}

int mfl_jwt_checkout_feature(mfl_module_data_t *module_data,
                             const char *feature, const char *version,
                             int num_lic)
{
    mfl_license_jwt_t *mfl = (mfl_license_jwt_t *)module_data;
    int status;
    fflush(NULL);
    char error_msg_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
    memset(error_msg_buffer, '\0', MFL_JWT_ERROR_MSG_BUFFER_SIZE);
    if (mfl == NULL) {
        return MFL_ERROR;
    }
    status = mfl_jwt_component_license_check(feature, mfl->required_usernames, error_msg_buffer);
    if (status != MFL_SUCCESS) {
        set_error(mfl, error_msg_buffer);
        // fflush(NULL);
    }
    return status;
}

int mfl_jwt_checkin_feature(mfl_module_data_t *module_data, const char *feature)
{
    mfl_license_jwt_t *mfl = (mfl_license_jwt_t *)module_data;
    if (mfl == NULL) {
        return MFL_ERROR;
    }

    return MFL_SUCCESS;
}

char *mfl_jwt_last_error(mfl_module_data_t *module_data)
{
    mfl_license_jwt_t *mfl = (mfl_license_jwt_t *)module_data;

    char *res = mfl->error_msg;
    return res;
}

int mfl_jwt_check_any_jwt_env_var_set()
{
    char *jwt_token;
    jwt_token = getenv("MODELON_LICENSE_USER_JWT");
    if (jwt_token != NULL) {
        return MFL_SUCCESS;
    }
    char *jwt_url;
    jwt_url = getenv("MODELON_LICENSE_USER_JWT_URL");
    if (jwt_url != NULL) {
        return MFL_SUCCESS;
    }
    return MFL_ERROR;
}

int mfl_jwt_unsetenv_any_jwt_env_var(void)
{
    unsetenv("MODELON_LICENSE_USER_JWT");
    unsetenv("MODELON_LICENSE_USER_JWT_URL");
}

/**
 * @brief Prints \p error_msg_input, if not NULL
 */
static void _snprintf_and_increment_error_msg_buffer(
    char **error_msg_buffer_current_position,
    size_t *error_msg_buffer_remaining_size, const char *error_msg_input)
{
    size_t error_msg_input_sz;
    if (error_msg_input == NULL) {
        return;
    }
    snprintf(*error_msg_buffer_current_position,
             *error_msg_buffer_remaining_size, "%s", error_msg_input);
    error_msg_input_sz = strlen(error_msg_input);
    *error_msg_buffer_current_position += error_msg_input_sz;
    *error_msg_buffer_remaining_size -= error_msg_input_sz;
}

void _print_to_error_msg_buffer(char *error_msg_buffer, char *error_msg_start)
{
    char *error_msg_buffer_current_position = error_msg_buffer;
    size_t error_msg_buffer_remaining_size = MFL_JWT_ERROR_MSG_BUFFER_SIZE;
    _snprintf_and_increment_error_msg_buffer(&error_msg_buffer_current_position,
                                             &error_msg_buffer_remaining_size,
                                             error_msg_start);
}

int mfl_jwt_get_entitlement_jwt_from_json_response(char *error_msg_buffer,
                                                   char **jwt_token,
                                                   char *json_response)
{
    int result = MFL_ERROR;
    int status = MFL_ERROR;
    json_t *toplevel_object_json;
    json_t *data_object_json;
    json_t *entitlement_object_json;
    const char *jwt_token_readonly_value;

    toplevel_object_json = json_loads(json_response, 0, NULL);
    if (!json_is_object(toplevel_object_json)) {
        snprintf(error_msg_buffer, MFL_JWT_ERROR_MSG_BUFFER_SIZE,
                 "error: response is not a json object: response:\n%s",
                 json_response);
        result = MFL_ERROR;
        goto error;
    }
    data_object_json = json_object_get(toplevel_object_json, "data");
    if (!json_is_object(data_object_json)) {
        snprintf(error_msg_buffer, MFL_JWT_ERROR_MSG_BUFFER_SIZE,
                 "error: value is not a json object: key \"data\" in response: "
                 "response:\n%s",
                 json_response);
        result = MFL_ERROR;
        goto error;
    }
    entitlement_object_json = json_object_get(data_object_json, "entitlement");
    jwt_token_readonly_value = json_string_value(entitlement_object_json);
    if (jwt_token_readonly_value == NULL) {
        snprintf(error_msg_buffer, MFL_JWT_ERROR_MSG_BUFFER_SIZE,
                 "error: value is not a json string: key \"entitlement\" in "
                 "\"data\" in response: response:\n%s",
                 json_response);
        result = MFL_ERROR;
        goto error;
    }

    // we need to strdup() the string jwt_token_readonly_value because it is
    // freed when toplevel_object_json is freed
    *jwt_token = strdup(jwt_token_readonly_value);

    result = MFL_SUCCESS;
error:
    json_decref(toplevel_object_json);
    return result;
}

/** Return MFL_SUCCESS on success, or MFL_ERROR on error.
 * Populates json_response with the token from handling the URL in the
 * environment variable MODELON_LICENSE_USER_JWT_URL Caller must free
 * json_response
 */
static int mfl_jwt_url(char **json_response, char *error_msg_buffer)
{
    char *url_str = getenv("MODELON_LICENSE_USER_JWT_URL");
    if (url_str == NULL) {
        return MFL_ERROR;
    } else if (strncmp(url_str, "file://", strlen("file://")) == 0) {
        return mfl_jwt_url_file(json_response, error_msg_buffer);
    } else if (strncmp(url_str, "http://", strlen("http://")) == 0 ||
               strncmp(url_str, "https://", strlen("https://")) == 0) {
        return mfl_jwt_url_http_and_https(json_response, error_msg_buffer);
    }

    const char *error_msg_start = NULL;
    char error_msg_input_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
    size_t error_msg_input_buffer_sz = MFL_JWT_ERROR_MSG_BUFFER_SIZE;
    memset(error_msg_input_buffer, '\0', error_msg_input_buffer_sz);
    error_msg_start =
        "error: MODELON_LICENSE_USER_JWT_URL=%s: URL does not start "
        "with a supported protocol. Supported protocols: "
        "'file://', 'http://', or 'https://'";
    snprintf(error_msg_input_buffer, error_msg_input_buffer_sz, error_msg_start,
             url_str);
    _print_to_error_msg_buffer(error_msg_buffer, error_msg_input_buffer);
    return MFL_ERROR;
}

/** Allocates a string and prints to it.
 * Returns MFL_SUCCESS on success, or MFL_ERROR on error.
 * *strp is set to NULL on error.
 * Caller must free(*strp).
 */
int mfl_jwt_util_asprintf(char *error_msg_buffer, char **strp, const char *fmt,
                          ...)
{
    int bytes_written = 0;
    va_list args;
    va_start(args, fmt);
    bytes_written = vasprintf(strp, fmt, args);
    va_end(args);
    if (bytes_written < 0) {
        const char *error_msg_start = NULL;
        char error_msg_input_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
        size_t error_msg_input_buffer_sz = MFL_JWT_ERROR_MSG_BUFFER_SIZE;
        memset(error_msg_input_buffer, '\0', error_msg_input_buffer_sz);
        error_msg_start = "error: asprintf() failed. error message: '%s'";
        snprintf(error_msg_input_buffer, error_msg_input_buffer_sz,
                 error_msg_start, strerror(errno));
        _print_to_error_msg_buffer(error_msg_buffer, error_msg_input_buffer);
        *strp = NULL;
        return MFL_ERROR;
    }
    return MFL_SUCCESS;
}

/** Read file into a null-terminated string.
 * Points 'out' to the string.
 * Returns number of bytes read, or 0 on error.
 * Caller must free(out).
 */
size_t mfl_jwt_util_read_file(char **out, FILE *fp, char *error_msg_buffer)
{
    size_t out_sz = 0;
    size_t out_capacity = 8192;
    char buffer[8192];
    char *buffer_p = buffer;
    size_t bytes_read = 0;
    char *out_p = NULL;

    *out = (char *)malloc(out_capacity * sizeof(**out));
    if (*out == NULL) {
        out_sz = 0;
        goto error;
    }
    out_p = *out;
    while (
        (bytes_read = fread(buffer_p, sizeof(*buffer_p), sizeof(buffer), fp))) {
        out_sz += bytes_read;
        if (out_sz >= out_capacity) {
            out_capacity = out_capacity * 2;
            *out = (char *)realloc(*out, out_capacity * sizeof(**out));
            if (*out == NULL) {
                out_sz = 0;
                goto error;
            }
            out_p = *out - (out_sz - bytes_read);
        }
        memcpy(out_p, buffer, bytes_read);
        out_p += bytes_read;
    }
    (*out)[out_sz] = '\0';
error:
    return out_sz;
}

static int mfl_jwt_url_file(char **jwt_token, char *error_msg_buffer)
{
    int result = MFL_ERROR;
    char *url_str = NULL;
    char *file_path = NULL;
    FILE *fp = NULL;
    size_t bytes_read = -1;

    url_str = getenv("MODELON_LICENSE_USER_JWT_URL");
    if (url_str == NULL) {
        result = MFL_ERROR;
        goto error;
    }
    file_path = url_str + strlen("file://");
    fp = fopen(file_path, "r");
    if (fp == NULL) {
        snprintf(error_msg_buffer, MFL_JWT_ERROR_MSG_BUFFER_SIZE, "%s: %s",
                 file_path, strerror(errno));
        LOGE("%s\n", error_msg_buffer);
        result = MFL_ERROR;
        goto error;
    }
    bytes_read = mfl_jwt_util_read_file(jwt_token, fp, error_msg_buffer);
    if (bytes_read == 0 || ferror(fp)) {
        _print_to_error_msg_buffer(
            error_msg_buffer,
            "error: could open but not read from file set in "
            "environment variable MODELON_LICENSE_USER_JWT_URL");
        result = MFL_ERROR;
        goto error;
    }
    result = MFL_SUCCESS;
error:
    if (fp != NULL) {
        fclose(fp);
    }
    return result;
}

/** Return MFL_SUCCESS on success, or MFL_ERROR on error.
 * Populates json_response with the token in the environment variable
 * MODELON_LICENSE_USER_JWT Caller must free json_response
 */
static int mfl_jwt_env_var(char **json_response)
{
    int result = MFL_ERROR;
    char *env_var = getenv("MODELON_LICENSE_USER_JWT");
    if (env_var == NULL) {
        result = MFL_ERROR;
        goto error;
    }
    *json_response = strdup(env_var);
    if (*json_response == NULL) {
        result = MFL_ERROR;
        goto error;
    }

    result = MFL_SUCCESS;
error:
    return result;
}

/** Return MFL_SUCCESS on success, or MFL_ERROR on error.
 * Populates jwt_token with the token. Common entrypoint to handle both cases:
 * 1. in the environment variable MODELON_LICENSE_USER_JWT
 * 2. from handling the URL in the environment variable
 * MODELON_LICENSE_USER_JWT_URL Caller must free jwt_token
 */
static int mfl_jwt_get_token_from_any_jwt_env_var(char **jwt_token,
                                                  char *error_msg_buffer)
{
    int result = MFL_ERROR;
    int status = MFL_ERROR;
    char *json_response = NULL;

    status = mfl_jwt_env_var(&json_response);
    if (status != MFL_SUCCESS) {
        status = mfl_jwt_url(&json_response, error_msg_buffer);
        if (status != MFL_SUCCESS) {
            result = status;
            goto error;
        }
    }

    mfl_jwt_get_entitlement_jwt_from_json_response(error_msg_buffer, jwt_token,
                                                   json_response);

    result = MFL_SUCCESS;
error:
    free(json_response);
    return result;
}

static int _jwt_decode_using_compiled_in_key(jwt_t **jwt, char *jwt_token,
                                             char *error_msg_buffer)
{
    int status;
    int i;
    int public_key_index;
    const char *jwt_kid;
    status = jwt_decode(jwt, jwt_token, NULL, 0);
    if (status != 0 || jwt == NULL) {
        _print_to_error_msg_buffer(
            error_msg_buffer, "error: decoding jwt failed when using no key");
        goto error;
    }
    jwt_kid = jwt_get_header(*jwt, "kid");
    if (jwt_kid == NULL) {
        _print_to_error_msg_buffer(error_msg_buffer,
                                   "error: header claim 'kid' not found");
        status = -1;
        goto error;
    }
    // find public key with kid jwt_kid
    DECLARE_PUBLIC_KEY_JWT_KEY_ID();
    public_key_index = -1;
    for (i = 0; i < PUBLIC_KEY_JWT_NUM; i++) {
        if (strcmp(PUBLIC_KEY_JWT_KEY_ID[i], jwt_kid) == 0) {
            public_key_index = i;
            break;
        }
    }
    if (public_key_index == -1) {
        const char *error_msg_start = NULL;
        const char *error_msg_description_jwt = NULL;
        const char *jwt_dump_str_result = NULL;
        char error_msg_input_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
        size_t error_msg_input_buffer_sz = MFL_JWT_ERROR_MSG_BUFFER_SIZE;
        memset(error_msg_input_buffer, '\0', error_msg_input_buffer_sz);
        error_msg_start = "error: public key with kid not found: kid: %s";
        snprintf(error_msg_input_buffer, error_msg_input_buffer_sz,
                 error_msg_start, jwt_kid);
        _print_to_error_msg_buffer(error_msg_buffer, error_msg_input_buffer);
        status = -2;
        goto error;
    }
    DECLARE_PUBLIC_KEY_JWT();
    DECLARE_PUBLIC_KEY_JWT_LEN();
    INITIALIZE_PUBLIC_KEY_JWT();
    status = jwt_decode(jwt, jwt_token, PUBLIC_KEY_JWT[public_key_index],
                        PUBLIC_KEY_JWT_LEN[public_key_index]);
    CLEAR_PUBLIC_KEY_JWT();
    if (status != 0 || jwt == NULL) {
        _print_to_error_msg_buffer(
            error_msg_buffer,
            "error: decoding jwt failed when using public key");
        goto error;
    }

error:
    return status;
}

static int mfl_jwt_check_username_in_required_usernames(char *username, char *required_usernames, char *error_msg_buffer)
{
    int result = MFL_ERROR;
    char *required_username = "example.email@example.com"; //TODO add loop over required_usernames
    if (!strcmp(username, required_username) == 0) {
        char *error_msg_buffer_current_position = error_msg_buffer;
        size_t error_msg_buffer_remaining_size =
            MFL_JWT_ERROR_MSG_BUFFER_SIZE;
        const char *error_msg_start = NULL;
        const char *error_msg_middle = NULL;
        const char *error_msg_description_jwt = NULL;
        char *jwt_dump_str_result = NULL;
        const char *error_msg_description_end = NULL;
        char error_msg_input_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
        size_t error_msg_input_buffer_sz = MFL_JWT_ERROR_MSG_BUFFER_SIZE;
        memset(error_msg_input_buffer, '\0', error_msg_input_buffer_sz);
        error_msg_start =
            "error: User '%s' is not licensed to use this library."
            "The users that are licensed to use this library are:\n%s";
        snprintf(error_msg_input_buffer, error_msg_input_buffer_sz,
                    error_msg_start, username, required_usernames);
        error_msg_description_end = "\n";
        _snprintf_and_increment_error_msg_buffer(
            &error_msg_buffer_current_position,
            &error_msg_buffer_remaining_size, error_msg_description_end);
        LOGE("%s\n", error_msg_buffer);
        goto error;
    }

    result = MFL_SUCCESS;
error:
    return result;
}


int mfl_jwt_component_license_check(const char *requested_feature,
                                    char *required_usernames,
                                    char *error_msg_buffer)
{
    int result = MFL_ERROR;
    int status;
    const char *FORMAT_VERSION = "1.0.0"; // The version of the token schema
    char *jwt_token = NULL;
    jwt_t *jwt = NULL;
    jwt_valid_t *jwt_valid = NULL;
    jwt_alg_t jwt_alg = JWT_ALG_RS256;
    const time_t now = time(NULL);

    char *features_list_json_str = NULL;
    json_t *features_list_json = NULL;
    size_t i = 0;
    json_t *feature_json = NULL;
    const char *feature_json_str = NULL;
    int requested_feature_found = 0;

    char *user_object_json_str = NULL;
    json_t *user_object_json = NULL;
    json_t *username_json = NULL;
    const char *username = NULL;

    status = jwt_valid_new(&jwt_valid, jwt_alg);
    if (status != 0 || jwt_valid == NULL) {
        _print_to_error_msg_buffer(error_msg_buffer,
                                   "error: creating JWT validation object");
        goto error;
    }
    // "now" is checked against "expiration time" and "not before" by
    // jwt_validate()
    jwt_valid_set_now(jwt_valid, now);
    // add grants for custom claims
    status = jwt_valid_add_grant(jwt_valid, "format_version", FORMAT_VERSION);
    if (status != 0) {
        _print_to_error_msg_buffer(
            error_msg_buffer,
            "error: adding grant to JWT validation object: format_version");
        goto error;
    }
    status =
        mfl_jwt_get_token_from_any_jwt_env_var(&jwt_token, error_msg_buffer);
    if (status != MFL_SUCCESS) {
        result = status;
        goto error;
    }
    status =
        _jwt_decode_using_compiled_in_key(&jwt, jwt_token, error_msg_buffer);
    if (status != 0 || jwt == NULL) {
        goto error;
    }

    // check that the jwt is valid
    status = jwt_validate(jwt, jwt_valid);
    if (status != 0) {
        char *error_msg_buffer_current_position = error_msg_buffer;
        size_t error_msg_buffer_remaining_size = MFL_JWT_ERROR_MSG_BUFFER_SIZE;
        // explain the validation failure
        {
            // check that the claim 'format_version' exists
            const char *format_version_json_str =
                jwt_get_grant(jwt, "format_version");
            if (format_version_json_str == NULL) {
                const char *error_msg_start = NULL;
                error_msg_start =
                    "error: jwt does not contain claim, or claim value is not "
                    "a json string: format_version\n";
                _snprintf_and_increment_error_msg_buffer(
                    &error_msg_buffer_current_position,
                    &error_msg_buffer_remaining_size, error_msg_start);
                goto jwt_validation_error;
            }
            // check that the claim 'format_version' has the required value
            // FORMAT_VERSION
            if (strcmp(format_version_json_str, FORMAT_VERSION) != 0) {
                const char *error_msg_start = NULL;
                const char *error_msg_description_jwt = NULL;
                const char *jwt_dump_str_result = NULL;
                char error_msg_input_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
                size_t error_msg_input_buffer_sz =
                    MFL_JWT_ERROR_MSG_BUFFER_SIZE;
                memset(error_msg_input_buffer, '\0', error_msg_input_buffer_sz);
                error_msg_start = "error: claim 'format_version': actual value "
                                  "does not match expected value:"
                                  " expected value: %s: actual value: %s\n";
                snprintf(error_msg_input_buffer, error_msg_input_buffer_sz,
                         error_msg_start, FORMAT_VERSION,
                         format_version_json_str);
                _snprintf_and_increment_error_msg_buffer(
                    &error_msg_buffer_current_position,
                    &error_msg_buffer_remaining_size, error_msg_input_buffer);
                goto jwt_validation_error;
            }
        }
    jwt_validation_error: {
        const char *error_msg_start = NULL;
        const char *error_msg_description_jwt = NULL;
        char *jwt_dump_str_result = NULL;
        char error_msg_input_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
        size_t error_msg_input_buffer_sz = MFL_JWT_ERROR_MSG_BUFFER_SIZE;
        memset(error_msg_input_buffer, '\0', error_msg_input_buffer_sz);
        error_msg_start = "error: jwt validation failed: status: %08x:\n";
        snprintf(error_msg_input_buffer, error_msg_input_buffer_sz,
                 error_msg_start, jwt_valid_get_status(jwt_valid));
        _snprintf_and_increment_error_msg_buffer(
            &error_msg_buffer_current_position,
            &error_msg_buffer_remaining_size, error_msg_input_buffer);
        error_msg_description_jwt = "\njwt:\n";
        _snprintf_and_increment_error_msg_buffer(
            &error_msg_buffer_current_position,
            &error_msg_buffer_remaining_size, error_msg_description_jwt);
        jwt_dump_str_result = jwt_dump_str(jwt, 1);
        _snprintf_and_increment_error_msg_buffer(
            &error_msg_buffer_current_position,
            &error_msg_buffer_remaining_size, jwt_dump_str_result);
        free(jwt_dump_str_result);
        goto error;
    }
    }

    // check that the "features" list contains the requested feature
    features_list_json_str = jwt_get_grants_json(jwt, "features");
    if (features_list_json_str == NULL) {
        const char *error_msg_start = NULL;
        const char *error_msg_description_jwt = NULL;
        char *jwt_dump_str_result = NULL;
        char *error_msg_buffer_current_position = error_msg_buffer;
        size_t error_msg_buffer_remaining_size = MFL_JWT_ERROR_MSG_BUFFER_SIZE;
        error_msg_start = "error: jwt does not contain claim: features\n";
        _snprintf_and_increment_error_msg_buffer(
            &error_msg_buffer_current_position,
            &error_msg_buffer_remaining_size, error_msg_start);
        error_msg_description_jwt = "\njwt:\n";
        _snprintf_and_increment_error_msg_buffer(
            &error_msg_buffer_current_position,
            &error_msg_buffer_remaining_size, error_msg_description_jwt);
        jwt_dump_str_result = jwt_dump_str(jwt, 1);
        _snprintf_and_increment_error_msg_buffer(
            &error_msg_buffer_current_position,
            &error_msg_buffer_remaining_size, jwt_dump_str_result);
        free(jwt_dump_str_result);
        goto error;
    }
    features_list_json = json_loads(features_list_json_str, 0, NULL);
    if (features_list_json == NULL) {
        const char *error_msg_start = NULL;
        const char *error_msg_description_jwt = NULL;
        char *jwt_dump_str_result = NULL;
        char *error_msg_buffer_current_position = error_msg_buffer;
        size_t error_msg_buffer_remaining_size = MFL_JWT_ERROR_MSG_BUFFER_SIZE;
        error_msg_start =
            "error: failed to load json: jwt claim 'features' json input:\n";
        _snprintf_and_increment_error_msg_buffer(
            &error_msg_buffer_current_position,
            &error_msg_buffer_remaining_size, error_msg_start);
        _snprintf_and_increment_error_msg_buffer(
            &error_msg_buffer_current_position,
            &error_msg_buffer_remaining_size, features_list_json_str);
        error_msg_description_jwt = "\n\njwt:\n";
        _snprintf_and_increment_error_msg_buffer(
            &error_msg_buffer_current_position,
            &error_msg_buffer_remaining_size, error_msg_description_jwt);
        jwt_dump_str_result = jwt_dump_str(jwt, 1);
        _snprintf_and_increment_error_msg_buffer(
            &error_msg_buffer_current_position,
            &error_msg_buffer_remaining_size, jwt_dump_str_result);
        free(jwt_dump_str_result);
        goto error;
    }
    if (!json_is_array(features_list_json)) {
        const char *error_msg_start = NULL;
        const char *error_msg_description_jwt = NULL;
        char *jwt_dump_str_result = NULL;
        char *error_msg_buffer_current_position = error_msg_buffer;
        size_t error_msg_buffer_remaining_size = MFL_JWT_ERROR_MSG_BUFFER_SIZE;
        error_msg_start =
            "error: not a json array: jwt claim 'features' json input:\n";
        _snprintf_and_increment_error_msg_buffer(
            &error_msg_buffer_current_position,
            &error_msg_buffer_remaining_size, error_msg_start);
        _snprintf_and_increment_error_msg_buffer(
            &error_msg_buffer_current_position,
            &error_msg_buffer_remaining_size, features_list_json_str);
        error_msg_description_jwt = "\n\njwt:\n";
        _snprintf_and_increment_error_msg_buffer(
            &error_msg_buffer_current_position,
            &error_msg_buffer_remaining_size, error_msg_description_jwt);
        jwt_dump_str_result = jwt_dump_str(jwt, 1);
        _snprintf_and_increment_error_msg_buffer(
            &error_msg_buffer_current_position,
            &error_msg_buffer_remaining_size, jwt_dump_str_result);
        free(jwt_dump_str_result);
        goto error;
    }
    json_array_foreach(features_list_json, i, feature_json)
    {
        feature_json_str =
            json_string_value(feature_json); // does not need to be freed
        if (feature_json_str == NULL) {
            char *json_dumps_result = NULL;
            char *jwt_dump_str_result = NULL;
            const char *error_msg_start;
            const char *error_msg_middle = NULL;
            const char *error_msg_description_jwt = NULL;
            const char *error_msg_description_end;
            char *error_msg_buffer_current_position = error_msg_buffer;
            size_t error_msg_buffer_remaining_size =
                MFL_JWT_ERROR_MSG_BUFFER_SIZE;

            error_msg_start = "error: not a json string: value: \n";
            _snprintf_and_increment_error_msg_buffer(
                &error_msg_buffer_current_position,
                &error_msg_buffer_remaining_size, error_msg_start);
            json_dumps_result = json_dumps(feature_json, JSON_ENCODE_ANY);
            _snprintf_and_increment_error_msg_buffer(
                &error_msg_buffer_current_position,
                &error_msg_buffer_remaining_size, json_dumps_result);
            free(json_dumps_result);

            error_msg_middle = "\n\njwt claim 'features' json input:\n";
            _snprintf_and_increment_error_msg_buffer(
                &error_msg_buffer_current_position,
                &error_msg_buffer_remaining_size, error_msg_middle);
            _snprintf_and_increment_error_msg_buffer(
                &error_msg_buffer_current_position,
                &error_msg_buffer_remaining_size, features_list_json_str);

            error_msg_description_jwt = "\n\njwt:\n";
            _snprintf_and_increment_error_msg_buffer(
                &error_msg_buffer_current_position,
                &error_msg_buffer_remaining_size, error_msg_description_jwt);
            jwt_dump_str_result = jwt_dump_str(jwt, 1);
            _snprintf_and_increment_error_msg_buffer(
                &error_msg_buffer_current_position,
                &error_msg_buffer_remaining_size, jwt_dump_str_result);
            free(jwt_dump_str_result);

            error_msg_description_end = "\n";
            _snprintf_and_increment_error_msg_buffer(
                &error_msg_buffer_current_position,
                &error_msg_buffer_remaining_size, error_msg_description_end);
            LOGE("%s\n", error_msg_buffer);
            goto error;
        }
        if (strcmp(feature_json_str, requested_feature) == 0) {
            requested_feature_found = 1;
            break;
        }
    }
    if (!requested_feature_found) {
        char *error_msg_buffer_current_position = error_msg_buffer;
        size_t error_msg_buffer_remaining_size = MFL_JWT_ERROR_MSG_BUFFER_SIZE;
        const char *error_msg_start = NULL;
        const char *error_msg_middle = NULL;
        const char *error_msg_description_jwt = NULL;
        char *jwt_dump_str_result = NULL;
        const char *error_msg_description_end = NULL;
        char error_msg_input_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
        size_t error_msg_input_buffer_sz = MFL_JWT_ERROR_MSG_BUFFER_SIZE;
        memset(error_msg_input_buffer, '\0', error_msg_input_buffer_sz);
        error_msg_start = "error: requested feature not found in jwt claim "
                          "'features': requested feature: %s";
        snprintf(error_msg_input_buffer, error_msg_input_buffer_sz,
                 error_msg_start, requested_feature);
        _snprintf_and_increment_error_msg_buffer(
            &error_msg_buffer_current_position,
            &error_msg_buffer_remaining_size, error_msg_input_buffer);
        error_msg_middle = "\n\njwt claim 'features' json input:\n";
        _snprintf_and_increment_error_msg_buffer(
            &error_msg_buffer_current_position,
            &error_msg_buffer_remaining_size, error_msg_middle);
        _snprintf_and_increment_error_msg_buffer(
            &error_msg_buffer_current_position,
            &error_msg_buffer_remaining_size, features_list_json_str);

        error_msg_description_jwt = "\n\njwt:\n";
        _snprintf_and_increment_error_msg_buffer(
            &error_msg_buffer_current_position,
            &error_msg_buffer_remaining_size, error_msg_description_jwt);
        jwt_dump_str_result = jwt_dump_str(jwt, 1);
        _snprintf_and_increment_error_msg_buffer(
            &error_msg_buffer_current_position,
            &error_msg_buffer_remaining_size, jwt_dump_str_result);
        free(jwt_dump_str_result);

        error_msg_description_end = "\n";
        _snprintf_and_increment_error_msg_buffer(
            &error_msg_buffer_current_position,
            &error_msg_buffer_remaining_size, error_msg_description_end);
        LOGE("%s\n", error_msg_buffer);
        goto error;
    }

    // check that the "user" object contains "username" in required_usernames
    {
        user_object_json_str = jwt_get_grants_json(jwt, "user");
        if (user_object_json_str == NULL) {
            const char *error_msg_start = NULL;
            const char *error_msg_description_jwt = NULL;
            char *jwt_dump_str_result = NULL;
            char *error_msg_buffer_current_position = error_msg_buffer;
            size_t error_msg_buffer_remaining_size =
                MFL_JWT_ERROR_MSG_BUFFER_SIZE;
            error_msg_start = "error: jwt does not contain claim: user\n";
            _snprintf_and_increment_error_msg_buffer(
                &error_msg_buffer_current_position,
                &error_msg_buffer_remaining_size, error_msg_start);
            error_msg_description_jwt = "\njwt:\n";
            _snprintf_and_increment_error_msg_buffer(
                &error_msg_buffer_current_position,
                &error_msg_buffer_remaining_size, error_msg_description_jwt);
            jwt_dump_str_result = jwt_dump_str(jwt, 1);
            _snprintf_and_increment_error_msg_buffer(
                &error_msg_buffer_current_position,
                &error_msg_buffer_remaining_size, jwt_dump_str_result);
            free(jwt_dump_str_result);
            goto error;
        }
        user_object_json = json_loads(user_object_json_str, 0, NULL);
        if (user_object_json == NULL) {
            const char *error_msg_start = NULL;
            const char *error_msg_description_jwt = NULL;
            char *jwt_dump_str_result = NULL;
            char *error_msg_buffer_current_position = error_msg_buffer;
            size_t error_msg_buffer_remaining_size =
                MFL_JWT_ERROR_MSG_BUFFER_SIZE;
            error_msg_start =
                "error: failed to load json: jwt claim 'user' json input:\n";
            _snprintf_and_increment_error_msg_buffer(
                &error_msg_buffer_current_position,
                &error_msg_buffer_remaining_size, error_msg_start);
            _snprintf_and_increment_error_msg_buffer(
                &error_msg_buffer_current_position,
                &error_msg_buffer_remaining_size, user_object_json_str);
            error_msg_description_jwt = "\n\njwt:\n";
            _snprintf_and_increment_error_msg_buffer(
                &error_msg_buffer_current_position,
                &error_msg_buffer_remaining_size, error_msg_description_jwt);
            jwt_dump_str_result = jwt_dump_str(jwt, 1);
            _snprintf_and_increment_error_msg_buffer(
                &error_msg_buffer_current_position,
                &error_msg_buffer_remaining_size, jwt_dump_str_result);
            free(jwt_dump_str_result);
            goto error;
        }
        if (!json_is_object(user_object_json)) {
            const char *error_msg_start = NULL;
            const char *error_msg_description_jwt = NULL;
            char *jwt_dump_str_result = NULL;
            char *error_msg_buffer_current_position = error_msg_buffer;
            size_t error_msg_buffer_remaining_size =
                MFL_JWT_ERROR_MSG_BUFFER_SIZE;
            error_msg_start =
                "error: not a json object: jwt claim 'user' json input:\n";
            _snprintf_and_increment_error_msg_buffer(
                &error_msg_buffer_current_position,
                &error_msg_buffer_remaining_size, error_msg_start);
            _snprintf_and_increment_error_msg_buffer(
                &error_msg_buffer_current_position,
                &error_msg_buffer_remaining_size, user_object_json_str);
            error_msg_description_jwt = "\n\njwt:\n";
            _snprintf_and_increment_error_msg_buffer(
                &error_msg_buffer_current_position,
                &error_msg_buffer_remaining_size, error_msg_description_jwt);
            jwt_dump_str_result = jwt_dump_str(jwt, 1);
            _snprintf_and_increment_error_msg_buffer(
                &error_msg_buffer_current_position,
                &error_msg_buffer_remaining_size, jwt_dump_str_result);
            free(jwt_dump_str_result);
            goto error;
        }
        username_json = json_object_get(user_object_json, "username");
        username = json_string_value(username_json);
        if (username == NULL) {
            char *json_dumps_result = NULL;
            char *jwt_dump_str_result = NULL;
            const char *error_msg_start;
            const char *error_msg_middle = NULL;
            const char *error_msg_description_jwt = NULL;
            const char *error_msg_description_end;
            char *error_msg_buffer_current_position = error_msg_buffer;
            size_t error_msg_buffer_remaining_size =
                MFL_JWT_ERROR_MSG_BUFFER_SIZE;

            error_msg_start = "error: 'username' not a json string: value: \n";
            _snprintf_and_increment_error_msg_buffer(
                &error_msg_buffer_current_position,
                &error_msg_buffer_remaining_size, error_msg_start);
            json_dumps_result = json_dumps(username_json, JSON_ENCODE_ANY);
            _snprintf_and_increment_error_msg_buffer(
                &error_msg_buffer_current_position,
                &error_msg_buffer_remaining_size, json_dumps_result);
            free(json_dumps_result);

            error_msg_middle = "\n\njwt claim 'user' json input:\n";
            _snprintf_and_increment_error_msg_buffer(
                &error_msg_buffer_current_position,
                &error_msg_buffer_remaining_size, error_msg_middle);
            _snprintf_and_increment_error_msg_buffer(
                &error_msg_buffer_current_position,
                &error_msg_buffer_remaining_size, user_object_json_str);

            error_msg_description_jwt = "\n\njwt:\n";
            _snprintf_and_increment_error_msg_buffer(
                &error_msg_buffer_current_position,
                &error_msg_buffer_remaining_size, error_msg_description_jwt);
            jwt_dump_str_result = jwt_dump_str(jwt, 1);
            _snprintf_and_increment_error_msg_buffer(
                &error_msg_buffer_current_position,
                &error_msg_buffer_remaining_size, jwt_dump_str_result);
            free(jwt_dump_str_result);

            error_msg_description_end = "\n";
            _snprintf_and_increment_error_msg_buffer(
                &error_msg_buffer_current_position,
                &error_msg_buffer_remaining_size, error_msg_description_end);
            LOGE("%s\n", error_msg_buffer);
            goto error;
        }
        
        status = mfl_jwt_check_username_in_required_usernames(username, required_usernames, error_msg_buffer);
        if (status != MFL_SUCCESS) {
            result = status;
            goto error;
        }
    }

    result = MFL_SUCCESS;
error:
    free(jwt_token);
    json_decref(user_object_json);
    free(user_object_json_str);
    json_decref(features_list_json);
    free(features_list_json_str);
    jwt_free(jwt);
    jwt_valid_free(jwt_valid);
    return result;
}
