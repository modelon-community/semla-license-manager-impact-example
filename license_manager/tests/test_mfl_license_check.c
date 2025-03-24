/*
 * Copyright (C) 2022 Modelon AB
 */
#define _XOPEN_SOURCE 700
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <jansson.h>
#include <jwt.h>
#include <unistd.h>
#endif
#include <check.h>

#include "mfl_common.h"
#include "mfl_interface.h"

#ifndef WIN32
#include "public_key_jwt.h"
#include "unit_test_util.h"

#include "mfl_jwt.h"
#include "mfl_jwt_curl.h"

#include "sslecho.h"
#endif

#define STR2(x) #x
#define STR(x) STR2(x)

#define TEST_REPORT_FN "report.xml"

static int _decode_json(json_t **json, char *json_response)
{
    int result = MFL_ERROR;
    int status;
    char error_msg_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
    char *jwt_token;
    jwt_t *jwt = NULL;
    char *returned_json = NULL;

    status = mfl_jwt_get_entitlement_jwt_from_json_response(
        error_msg_buffer, &jwt_token, json_response);
    if (status == MFL_ERROR) {
        ck_abort_msg(error_msg_buffer);
    }

    DECLARE_PUBLIC_KEY_JWT();
    DECLARE_PUBLIC_KEY_JWT_LEN();
    INITIALIZE_PUBLIC_KEY_JWT();
    status = jwt_decode(&jwt, jwt_token,
                        PUBLIC_KEY_JWT[UNIT_TEST_PUBLIC_KEY_JWT_KEY_INDEX],
                        PUBLIC_KEY_JWT_LEN[UNIT_TEST_PUBLIC_KEY_JWT_KEY_INDEX]);
    CLEAR_PUBLIC_KEY_JWT();
    if (status != 0 || jwt == NULL) {
        fprintf(stderr, "jwt_decode() failed\n");
        goto error;
    }
    returned_json = jwt_get_grants_json(jwt, NULL);
    *json = json_loads(returned_json, 0, NULL);
    result = MFL_SUCCESS;
error:
    jwt_free(jwt);
    free(returned_json);
    return result;
}

static void _wrap_jwt_token_in_json_response(char **json_response,
                                             char *jwt_token)
{
    char error_msg_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
    int status = MFL_ERROR;

    status = mfl_jwt_util_asprintf(error_msg_buffer, json_response,
                                   "{\"data\": {\"entitlement\": \"%s\"}}",
                                   jwt_token);
    if (status != MFL_SUCCESS) {
        ck_abort_msg(error_msg_buffer);
    }
}

static int _encode_json(json_t *json, char **json_response)
{
    int result = MFL_ERROR;
    int status = MFL_ERROR;
    char *json_str;
    jwt_t *jwt;
    jwt_alg_t jwt_alg = JWT_ALG_RS256;
    char *jwt_key;
    size_t jwt_key_sz;
    char *jwt_token;

    status = jwt_new(&jwt);
    if (status != 0 || jwt == NULL) {
        fprintf(stderr, "jwt_new() failed\n");
        goto error;
    }
    DECLARE_PUBLIC_KEY_JWT_KEY_ID();
    status = jwt_add_header(
        jwt, "kid", PUBLIC_KEY_JWT_KEY_ID[UNIT_TEST_PUBLIC_KEY_JWT_KEY_INDEX]);
    if (status != 0) {
        fprintf(stderr, "jwt_add_header() failed\n");
        goto error;
    }
    json_str = json_dumps(json, 0);
    ck_assert_ptr_ne(json_str, NULL);
    status = jwt_add_grants_json(jwt, json_str);
    if (status != 0) {
        fprintf(stderr, "jwt_add_grants_json() failed\n");
        goto error;
    }
    read_jwt_private_key_from_jwt_key_dir(&jwt_key, &jwt_key_sz);
    status = jwt_set_alg(jwt, jwt_alg, jwt_key, jwt_key_sz);
    if (status < 0) {
        fprintf(stderr, "jwt_set_alg() failed\n");
        goto error;
    }
    jwt_token = jwt_encode_str(jwt);
    _wrap_jwt_token_in_json_response(json_response, jwt_token);
    result = MFL_SUCCESS;
error:
    free(jwt_token);
    free(json_str);
    jwt_free(jwt);
    return result;
}

static int _encode_json_without_kid_header_claim(json_t *json,
                                                 char **json_response)
{
    int result = MFL_ERROR;
    int status = MFL_ERROR;
    char *json_str = NULL;
    jwt_t *jwt;
    jwt_alg_t jwt_alg = JWT_ALG_RS256;
    char *jwt_key;
    size_t jwt_key_sz;
    char *jwt_token = NULL;

    status = jwt_new(&jwt);
    if (status != 0 || jwt == NULL) {
        fprintf(stderr, "jwt_new() failed\n");
        goto error;
    }

    // Difference with _encode_json() here: No 'kid' header claim is added.

    json_str = json_dumps(json, 0);
    ck_assert_ptr_ne(json_str, NULL);
    status = jwt_add_grants_json(jwt, json_str);
    if (status != 0) {
        fprintf(stderr, "jwt_add_grants_json() failed\n");
        goto error;
    }
    read_jwt_private_key_from_jwt_key_dir(&jwt_key, &jwt_key_sz);
    status = jwt_set_alg(jwt, jwt_alg, jwt_key, jwt_key_sz);
    if (status < 0) {
        fprintf(stderr, "jwt_set_alg() failed\n");
        goto error;
    }
    jwt_token = jwt_encode_str(jwt);
    _wrap_jwt_token_in_json_response(json_response, jwt_token);
    result = MFL_SUCCESS;
error:
    free(jwt_token);
    free(json_str);
    jwt_free(jwt);
    return result;
}

static int _encode_json_with_nonexistent_kid(json_t *json, char **json_response)
{
    int result = MFL_ERROR;
    int status = MFL_ERROR;
    char *json_str = NULL;
    jwt_t *jwt;
    jwt_alg_t jwt_alg = JWT_ALG_RS256;
    char *jwt_key;
    size_t jwt_key_sz;
    char *jwt_token = NULL;

    status = jwt_new(&jwt);
    if (status != 0 || jwt == NULL) {
        fprintf(stderr, "jwt_new() failed\n");
        goto error;
    }

    // Difference with _encode_json() here: Use a nonexistent kid
    // "nonexistent-kid".
    status = jwt_add_header(jwt, "kid", "nonexistent-kid");
    if (status != 0) {
        fprintf(stderr, "jwt_add_header() failed\n");
        goto error;
    }
    json_str = json_dumps(json, 0);
    ck_assert_ptr_ne(json_str, NULL);
    status = jwt_add_grants_json(jwt, json_str);
    if (status != 0) {
        fprintf(stderr, "jwt_add_grants_json() failed\n");
        goto error;
    }
    read_jwt_private_key_from_jwt_key_dir(&jwt_key, &jwt_key_sz);
    status = jwt_set_alg(jwt, jwt_alg, jwt_key, jwt_key_sz);
    if (status < 0) {
        fprintf(stderr, "jwt_set_alg() failed\n");
        goto error;
    }
    jwt_token = jwt_encode_str(jwt);
    _wrap_jwt_token_in_json_response(json_response, jwt_token);
    result = MFL_SUCCESS;
error:
    free(jwt_token);
    free(json_str);
    jwt_free(jwt);
    return result;
}

static void _get_tmp_dir(char **tmp_dir)
{
    *tmp_dir = getenv("TMPDIR");
    if (*tmp_dir == NULL) {
        *tmp_dir = "/tmp";
    }
    *tmp_dir = realpath(*tmp_dir, NULL);
}

/**
 * Caller must free tmp_dir.
 */
static void _create_tmp_dir(char **tmp_dir, char *tmp_dir_name_template)
{
    char *toplevel_tmp_dir = NULL;
    _get_tmp_dir(&toplevel_tmp_dir);
    size_t tmp_dir_sz =
        strlen(toplevel_tmp_dir) + strlen("/") + strlen(tmp_dir_name_template);
    *tmp_dir = malloc((tmp_dir_sz + 1) * sizeof(**tmp_dir));
    sprintf(*tmp_dir, "%s%s%s", toplevel_tmp_dir, "/", tmp_dir_name_template);
    *tmp_dir = mkdtemp(*tmp_dir);
    free(toplevel_tmp_dir);
}

static void _create_tmp_file(FILE **tmp_fp, char **tmp_file,
                             char *tmp_file_name_template)
{
    int tmp_fd = -1;
    char *toplevel_tmp_dir = NULL;
    _get_tmp_dir(&toplevel_tmp_dir);
    size_t tmp_file_name_sz =
        strlen(toplevel_tmp_dir) + strlen("/") + strlen(tmp_file_name_template);
    *tmp_file = malloc((tmp_file_name_sz + 1) * sizeof(**tmp_file));
    sprintf(*tmp_file, "%s%s%s", toplevel_tmp_dir, "/", tmp_file_name_template);
    tmp_fd = mkstemp(*tmp_file);
    ck_assert_int_ne(tmp_fd, -1);
    *tmp_fp = fdopen(tmp_fd, "w");
    free(toplevel_tmp_dir);
}

static int _write_to_tmp_file(char **tmp_file, char *tmp_file_name_template,
                              char *format, ...)
{
    FILE *tmp_fp = NULL;
    _create_tmp_file(&tmp_fp, tmp_file, tmp_file_name_template);
    ck_assert_ptr_ne(tmp_fp, NULL);
    va_list args;
    va_start(args, format);
    size_t bytes_written = vfprintf(tmp_fp, format, args);
    va_end(args);
    // assert bytes_written >= 0 (because bytes_written < 0 if error)
    ck_assert_int_ge(bytes_written, 0);
    int status = fclose(tmp_fp);
    ck_assert_int_eq(status, 0);
    return bytes_written;
}

START_TEST(test_mfl_jwt_checkout_checkin)
{
#ifdef WIN32
    return; // skip on windows
#endif
    int status;
    mfl_license_t *mfl;

    // The times are set such that "now" = "iat", and "now" is between nbf ("not
    // before") and exp ("expiration time")
    const time_t now = time(NULL); // current time in seconds since the Epoch
    const time_t iat = now;
    const time_t nbf = now - 60;   // now - 1 minute
    const time_t exp = now + 3600; // now + 1 hour

    // check that 'now' is the same size as long, so that the use of "%ld" in
    // the sprintf below works. The width of time_t is platform-specific. This
    // may fail on platforms other than linux.
    ck_assert_int_eq(sizeof(now), sizeof(long));

    char jsonbuf[1024];
    // Keep json alphabetically sorted and no newlines for easy comparison.
    // This is a valid jwt.
    sprintf(jsonbuf,
            "{"
            // expiration time
            "\"exp\":%ld,"
            "\"features\":["
            "\"Feature1\","
            "\"Feature2\""
            "],"
            "\"format_version\":\"1.0.0\","
            // issued at (unused by jwt_validate())
            "\"iat\":%ld,"
            // not before
            "\"nbf\":%ld,"
            "\"user\": {"
            "\"id\": \"example-id\","
            "\"username\": \"example.email@example.com\""
            "}"
            "}",
            exp, iat, nbf);
    json_t *json = json_loads(jsonbuf, 0, NULL);
    // feature to check out from the 'features' list in the json above
    char *requested_feature_existant = "Feature2";
    char *licensed_users_existant = "example.email@example.com";
    char *json_str = NULL;
    json_t *json2 = NULL;
    char *json2_str = NULL;

    char *jwt_token;

    // test jwt token, and set up jwt token for the following tests
    mfl_jwt_unsetenv_any_jwt_env_var();
    status = _encode_json(json, &jwt_token);
    ck_assert_int_eq(status, MFL_SUCCESS);
    setenv("MODELON_LICENSE_USER_JWT", jwt_token, 1);
    jwt_token = getenv("MODELON_LICENSE_USER_JWT");
    status = _decode_json(&json2, jwt_token);
    ck_assert_int_eq(status, MFL_SUCCESS);
    json_str = json_dumps(json, 0);
    json2_str = json_dumps(json2, 0);
    ck_assert_str_eq(json_str, json2_str);
    json_decref(json);
    free(json_str);
    json_decref(json2);
    free(json2_str);

    // test requested feature
    {
        char error_msg_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
        mfl_jwt_unsetenv_any_jwt_env_var();
        setenv("MODELON_LICENSE_USER_JWT", jwt_token, 1);
        status = mfl_jwt_component_license_check(requested_feature_existant,
                                                 licensed_users_existant,
                                                 error_msg_buffer);
        ck_assert_ptr_ne(error_msg_buffer, NULL);
        if (status == MFL_ERROR) {
            // fail the test and output the error message
            ck_abort_msg(error_msg_buffer);
        }
        ck_assert_int_eq(status, MFL_SUCCESS);
    }

    // test https url
    {
        char error_msg_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
        char *JWT_URL = "https://127.0.0.1:4433";
        mfl_jwt_unsetenv_any_jwt_env_var();
        setenv("MODELON_LICENSE_USER_JWT", jwt_token, 1);
        setenv("MODELON_LICENSE_USER_JWT_URL", JWT_URL, 1);
        // chdir to where the key and cert .pem files needed by sslecho server
        // are located
        status = chdir("./sslecho");
        ck_assert_int_eq(status, 0);
        sslecho_server_fork();
        sleep(1);
        unsetenv("MODELON_LICENSE_USER_JWT");
        unsetenv("MODELON_LICENSE_USER_JWT_URL");
        setenv("MODELON_LICENSE_USER_JWT_URL", JWT_URL, 1);
        // workaround for self-signed certificate not verifying
        setenv("MFL_SSL_NO_VERIFY", "1", 1);
        status = mfl_jwt_component_license_check(requested_feature_existant,
                                                 licensed_users_existant,
                                                 error_msg_buffer);
        ck_assert_ptr_ne(error_msg_buffer, NULL);
        if (status == MFL_ERROR) {
            // fail the test and output the error message
            ck_abort_msg(error_msg_buffer);
        }
        ck_assert_int_eq(status, MFL_SUCCESS);
        status = chdir("../");
        ck_assert_int_eq(status, 0);
    }

    // test https url when the server is not started, then the error message
    // should be: "error: command failed"
    {
        char error_msg_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
        char *requested_feature_existant;
        const char *expected_error_message_start;
        char *actual_error_message_start;
        char *JWT_URL = "https://127.0.0.1:4433";
        mfl_jwt_unsetenv_any_jwt_env_var();
        setenv("MODELON_LICENSE_USER_JWT_URL", JWT_URL, 1);
        // workaround for self-signed certificate not verifying
        setenv("MFL_SSL_NO_VERIFY", "1", 1);
        // feature to check out from the 'features' list in the json above
        requested_feature_existant = "Feature1";
        expected_error_message_start =
            "curl call failed: Couldn't connect to server";
        status = mfl_jwt_component_license_check(requested_feature_existant,
                                                 licensed_users_existant,
                                                 error_msg_buffer);
        ck_assert_int_eq(status, MFL_ERROR);
        ck_assert_ptr_ne(error_msg_buffer, NULL);
        actual_error_message_start =
            strndup(error_msg_buffer, strlen(expected_error_message_start));
        ck_assert_str_eq(actual_error_message_start,
                         expected_error_message_start);
        free(actual_error_message_start);
    }

    // test file url
    {
        char error_msg_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
        mfl_jwt_unsetenv_any_jwt_env_var();
        int jwt_token_sz = strlen(jwt_token);
        char *tmp_file_name = NULL;
        size_t bytes_written =
            _write_to_tmp_file(&tmp_file_name, "jwt_token_XXXXXX", jwt_token);

        ck_assert_int_eq(bytes_written, jwt_token_sz);
        size_t tmp_file_url_sz = strlen("file://") + strlen(tmp_file_name);
        char *tmp_file_url =
            malloc((tmp_file_url_sz + 1) * sizeof(*tmp_file_url));
        sprintf(tmp_file_url, "%s%s", "file://", tmp_file_name);
        setenv("MODELON_LICENSE_USER_JWT_URL", tmp_file_url, 1);
        status = mfl_jwt_component_license_check(requested_feature_existant,
                                                 licensed_users_existant,
                                                 error_msg_buffer);
        if (status == MFL_ERROR) {
            // fail the test and output the error message
            ck_abort_msg(error_msg_buffer);
        }
        ck_assert_int_eq(status, MFL_SUCCESS);
        status = unlink(tmp_file_name);
        ck_assert_int_eq(status, 0);
        free(tmp_file_name);
    }

    // test file url -- nonexistent file returns error message
    {
        char error_msg_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
        mfl_jwt_unsetenv_any_jwt_env_var();
        setenv("MODELON_LICENSE_USER_JWT_URL", "file:///nonexistent/file", 1);
        status = mfl_jwt_component_license_check(requested_feature_existant,
                                                 licensed_users_existant,
                                                 error_msg_buffer);
        ck_assert_int_eq(status, MFL_ERROR);
    }

    // test invalid url without a protocol ("https://") part -- returns error
    // message
    {
        char error_msg_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
        const char *expected_error_message_start;
        char *actual_error_message_start;
        mfl_jwt_unsetenv_any_jwt_env_var();
        setenv("MODELON_LICENSE_USER_JWT_URL", "127.0.0.1", 1);
        expected_error_message_start =
            "error: MODELON_LICENSE_USER_JWT_URL=127.0.0.1: URL does not start "
            "with a supported protocol. Supported protocols: 'file://', "
            "'http://', or 'https://'";
        status = mfl_jwt_component_license_check(requested_feature_existant,
                                                 licensed_users_existant,
                                                 error_msg_buffer);
        ck_assert_int_eq(status, MFL_ERROR);
        ck_assert_ptr_ne(error_msg_buffer, NULL);
        actual_error_message_start =
            strndup(error_msg_buffer, strlen(expected_error_message_start));
        ck_assert_str_eq(actual_error_message_start,
                         expected_error_message_start);
        free(actual_error_message_start);
    }

    // test using mfl_interface
    // Also: test with a license file with several users, and with {Windows,
    // Mac, Unix} line endings. Covers both the code that parses the license
    // file and the code that finds the user from the jwt in the list of users
    // from the license file.
    {
        char error_msg_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
        mfl_jwt_unsetenv_any_jwt_env_var();
        setenv("MODELON_LICENSE_USER_JWT", jwt_token, 1);
        char *version = "1.0";
        int num_lic = 1;
        int bytes_written = -1;

        // create mock encrypted library as a temp dir
        char *library_path = NULL;
        _create_tmp_dir(&library_path,
                        "test_mfl_license_check_mock_encrypted_library_XXXXXX");

        // write decrypted package.mo to library
        char *decrypted_package_mo_path = NULL;
        FILE *decrypted_package_mo_fp = NULL;
        bytes_written = asprintf(&decrypted_package_mo_path, "%s/%s",
                                 library_path, "package.mo");
        ck_assert_int_ge(bytes_written, 0);
        decrypted_package_mo_fp = fopen(decrypted_package_mo_path, "w");
        fprintf(decrypted_package_mo_fp, "package P\n"
                                         "end P;\n");
        status = fclose(decrypted_package_mo_fp);
        ck_assert_int_eq(status, 0);

        // write decrypted license file to library
        char *decrypted_license_file_path = NULL;
        FILE *decrypted_license_file_fp = NULL;
        bytes_written =
            asprintf(&decrypted_license_file_path, "%s/%s", library_path,
                     STR(MFL_JWT_LICENSE_FILE_FILENAME));
        ck_assert_int_ge(bytes_written, 0);
        decrypted_license_file_fp = fopen(decrypted_license_file_path, "w");
        fprintf(decrypted_license_file_fp,
                "model license\n"
                "/*\n"
                "other.user1@example.com\n"
                "%s\r\n"                    // <--- Windows line ending
                "other.user2@example.com\r" // <-- Mac line ending
                "*/\n"
                "end license;\n",
                licensed_users_existant);
        status = fclose(decrypted_license_file_fp);
        ck_assert_int_eq(status, 0);

        // encrypt package.mo to package.moc
        char *encrypted_package_mo_path = NULL;
        char *encrypted_package_mo_filename_original = NULL;
        char *encrypted_package_mo_filename = NULL;
        FILE *encrypted_package_mo_fp = NULL;
        char *encrypt_package_mo_command = NULL;
        bytes_written = asprintf(&encrypted_package_mo_path, "%s/%sc",
                                 library_path, "package.mo");
        ck_assert_int_ge(bytes_written, 0);
        // basename() man page recommends passing in a copy of the string
        // because it may be modified depending on how the function is
        // implemented
        encrypted_package_mo_filename_original =
            strdup(encrypted_package_mo_path);
        ck_assert_ptr_ne(encrypted_package_mo_filename_original, NULL);
        encrypted_package_mo_filename =
            basename(encrypted_package_mo_filename_original);
        bytes_written = asprintf(&encrypt_package_mo_command,
                                 "../../../encrypt_file %s %s %s",
                                 decrypted_package_mo_path,
                                 encrypted_package_mo_filename, library_path);
        ck_assert_int_ge(bytes_written, 0);
        status = system(encrypt_package_mo_command);
        ck_assert_int_eq(status, 0);

        // encrypt license file from .mo to .moc
        char *encrypted_license_file_path = NULL;
        char *encrypted_license_file_filename_original = NULL;
        char *encrypted_license_file_filename = NULL;
        FILE *encrypted_license_file_fp = NULL;
        char *encrypt_license_file_command = NULL;
        bytes_written =
            asprintf(&encrypted_license_file_path, "%s/%sc", library_path,
                     STR(MFL_JWT_LICENSE_FILE_FILENAME));
        encrypted_license_file_filename_original =
            strdup(encrypted_license_file_path);
        ck_assert_ptr_ne(encrypted_license_file_filename_original, NULL);
        encrypted_license_file_filename =
            basename(encrypted_license_file_filename_original);
        ck_assert_int_ge(bytes_written, 0);
        bytes_written = asprintf(&encrypt_license_file_command,
                                 "../../../encrypt_file %s %s %s",
                                 decrypted_license_file_path,
                                 encrypted_license_file_filename, library_path);
        ck_assert_int_ge(bytes_written, 0);
        status = system(encrypt_license_file_command);
        ck_assert_int_eq(status, 0);

        // remove the .mo files (but keep the .moc files) -- the library is now
        // encrypted
        status = unlink(decrypted_license_file_path);
        ck_assert_int_eq(status, 0);
        status = unlink(decrypted_package_mo_path);
        ck_assert_int_eq(status, 0);

        // do the test
        mfl = mfl_license_new();
        ck_assert_ptr_ne(mfl, NULL);
        status = mfl_initialize(mfl, library_path);
        if (status != MFL_SUCCESS) {
            ck_abort_msg(mfl_last_error(mfl));
        }
        ck_assert_int_eq(status, MFL_SUCCESS);
        status = mfl_checkout_feature(mfl, requested_feature_existant, version,
                                      num_lic);
        if (status != MFL_SUCCESS) {
            ck_abort_msg(mfl_last_error(mfl));
        }
        ck_assert_int_eq(status, MFL_SUCCESS);
        status = mfl_checkin_feature(mfl, requested_feature_existant);
        ck_assert_int_eq(status, MFL_SUCCESS);
        mfl_license_free(mfl);

        // cleanup
        free(encrypted_package_mo_filename_original);
        free(encrypt_package_mo_command);
        status = unlink(encrypted_package_mo_path);
        ck_assert_int_eq(status, 0);
        free(encrypted_package_mo_path);

        free(encrypted_license_file_filename_original);
        free(encrypt_license_file_command);
        status = unlink(encrypted_license_file_path);
        ck_assert_int_eq(status, 0);
        free(encrypted_license_file_path);

        free(decrypted_license_file_path);

        free(decrypted_package_mo_path);

        status = rmdir(library_path);
        ck_assert_int_eq(status, 0);
    }

    // test "error: header claim 'kid' not found"
    {
        char error_msg_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
        char jsonbuf[1024];
        json_t *json;
        char *requested_feature_existant;
        char *jwt_token;
        const char *expected_error_message_start;
        char *actual_error_message_start;
        mfl_jwt_unsetenv_any_jwt_env_var();
        // Keep json alphabetically sorted and no newlines for easy comparison.
        sprintf(jsonbuf,
                "{"
                // expiration time
                "\"exp\":%ld,"
                "\"features\":["
                "\"Feature1\","
                "\"Feature2\""
                "],"
                "\"format_version\":\"1.0.0\","
                // issued at (unused by jwt_validate())
                "\"iat\":%ld,"
                // not before
                "\"nbf\":%ld"
                "}",
                exp, iat, nbf);
        json = json_loads(jsonbuf, 0, NULL);
        ck_assert_ptr_ne(json, NULL);
        // feature to check out from the 'features' list in the json above
        requested_feature_existant = "Feature1";
        status = _encode_json_without_kid_header_claim(json, &jwt_token);
        ck_assert_int_eq(status, MFL_SUCCESS);
        setenv("MODELON_LICENSE_USER_JWT", jwt_token, 1);
        expected_error_message_start = "error: header claim 'kid' not found";
        status = mfl_jwt_component_license_check(requested_feature_existant,
                                                 licensed_users_existant,
                                                 error_msg_buffer);
        ck_assert_int_eq(status, MFL_ERROR);
        ck_assert_ptr_ne(error_msg_buffer, NULL);
        actual_error_message_start =
            strndup(error_msg_buffer, strlen(expected_error_message_start));
        ck_assert_str_eq(actual_error_message_start,
                         expected_error_message_start);
        free(actual_error_message_start);
    }

    // test "error: public key with kid not found"
    {
        char error_msg_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
        char jsonbuf[1024];
        json_t *json;
        char *requested_feature_existant;
        char *jwt_token;
        const char *expected_error_message_start;
        char *actual_error_message_start;
        mfl_jwt_unsetenv_any_jwt_env_var();
        // Keep json alphabetically sorted and no newlines for easy comparison.
        sprintf(jsonbuf,
                "{"
                // expiration time
                "\"exp\":%ld,"
                "\"features\":["
                "\"Feature1\","
                "\"Feature2\""
                "],"
                "\"format_version\":\"1.0.0\","
                // issued at (unused by jwt_validate())
                "\"iat\":%ld,"
                // not before
                "\"nbf\":%ld"
                "}",
                exp, iat, nbf);
        json = json_loads(jsonbuf, 0, NULL);
        ck_assert_ptr_ne(json, NULL);
        // feature to check out from the 'features' list in the json above
        requested_feature_existant = "Feature1";
        status = _encode_json_with_nonexistent_kid(json, &jwt_token);
        ck_assert_int_eq(status, MFL_SUCCESS);
        setenv("MODELON_LICENSE_USER_JWT", jwt_token, 1);
        expected_error_message_start = "error: public key with kid not found";
        status = mfl_jwt_component_license_check(requested_feature_existant,
                                                 licensed_users_existant,
                                                 error_msg_buffer);
        ck_assert_int_eq(status, MFL_ERROR);
        ck_assert_ptr_ne(error_msg_buffer, NULL);
        actual_error_message_start =
            strndup(error_msg_buffer, strlen(expected_error_message_start));
        ck_assert_str_eq(actual_error_message_start,
                         expected_error_message_start);
        free(actual_error_message_start);
    }

    // test "error: jwt does not contain claim, or claim value is not a json
    // string: format_version"
    {
        char error_msg_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
        char jsonbuf[1024];
        json_t *json;
        char *requested_feature_existant;
        char *jwt_token;
        const char *expected_error_message_start;
        char *actual_error_message_start;
        mfl_jwt_unsetenv_any_jwt_env_var();
        // Keep json alphabetically sorted and no newlines for easy comparison.
        sprintf(jsonbuf,
                "{"
                // expiration time
                "\"exp\":%ld,"
                "\"features\":["
                "\"Feature1\","
                "\"Feature2\""
                "],"

                // No "format_version" claim in this jwt.
                // This ensures that jwt_validate() fails,
                // produces the error message we want to test

                // issued at (unused by jwt_validate())
                "\"iat\":%ld,"
                // not before
                "\"nbf\":%ld"
                "}",
                exp, iat, nbf);
        json = json_loads(jsonbuf, 0, NULL);
        ck_assert_ptr_ne(json, NULL);
        // feature to check out from the 'features' list in the json above
        requested_feature_existant = "Feature1";
        status = _encode_json(json, &jwt_token);
        ck_assert_int_eq(status, MFL_SUCCESS);
        setenv("MODELON_LICENSE_USER_JWT", jwt_token, 1);
        expected_error_message_start =
            "error: jwt does not contain claim, or claim value is not a json "
            "string: format_version";
        status = mfl_jwt_component_license_check(requested_feature_existant,
                                                 licensed_users_existant,
                                                 error_msg_buffer);
        ck_assert_int_eq(status, MFL_ERROR);
        ck_assert_ptr_ne(error_msg_buffer, NULL);
        actual_error_message_start =
            strndup(error_msg_buffer, strlen(expected_error_message_start));
        ck_assert_str_eq(actual_error_message_start,
                         expected_error_message_start);
        free(actual_error_message_start);
    }

    // test when claim value is not a json string: "error: jwt does not contain
    // claim, or claim value is not a json string: format_version"
    {
        char error_msg_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
        char jsonbuf[1024];
        json_t *json;
        char *requested_feature_existant;
        char *jwt_token;
        const char *expected_error_message_start;
        char *actual_error_message_start;
        mfl_jwt_unsetenv_any_jwt_env_var();
        // Keep json alphabetically sorted and no newlines for easy comparison.
        sprintf(jsonbuf,
                "{"
                // expiration time
                "\"exp\":%ld,"
                "\"features\":["
                "\"Feature1\","
                "\"Feature2\""
                "],"

                // "format_version" is not a json string but a json number
                // This ensures that jwt_validate() fails,
                // produces the error message we want to test
                "\"format_version\":1234,"

                // issued at (unused by jwt_validate())
                "\"iat\":%ld,"
                // not before
                "\"nbf\":%ld"
                "}",
                exp, iat, nbf);
        json = json_loads(jsonbuf, 0, NULL);
        ck_assert_ptr_ne(json, NULL);
        // feature to check out from the 'features' list in the json above
        requested_feature_existant = "Feature1";
        status = _encode_json(json, &jwt_token);
        ck_assert_int_eq(status, MFL_SUCCESS);
        setenv("MODELON_LICENSE_USER_JWT", jwt_token, 1);
        expected_error_message_start =
            "error: jwt does not contain claim, or claim value is not a json "
            "string: format_version";
        status = mfl_jwt_component_license_check(requested_feature_existant,
                                                 licensed_users_existant,
                                                 error_msg_buffer);
        ck_assert_int_eq(status, MFL_ERROR);
        ck_assert_ptr_ne(error_msg_buffer, NULL);
        actual_error_message_start =
            strndup(error_msg_buffer, strlen(expected_error_message_start));
        ck_assert_str_eq(actual_error_message_start,
                         expected_error_message_start);
        free(actual_error_message_start);
    }

    // test "error: claim 'format_version': actual value does not match expected
    // value:"
    {
        char error_msg_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
        char jsonbuf[1024];
        json_t *json;
        char *requested_feature_existant;
        char *jwt_token;
        const char *expected_error_message_start;
        char *actual_error_message_start;
        mfl_jwt_unsetenv_any_jwt_env_var();
        // Keep json alphabetically sorted and no newlines for easy comparison.
        sprintf(
            jsonbuf,
            "{"
            // expiration time
            "\"exp\":%ld,"
            "\"features\":["
            "\"Feature1\","
            "\"Feature2\""
            "],"
            "\"format_version\":\"0.0.0\"," // <--- This causes the error we
                                            // want to test, "0.0.0" != "1.0.0"
                                            // (current FORMAT_VERSION value)
            // issued at (unused by jwt_validate())
            "\"iat\":%ld,"
            // not before
            "\"nbf\":%ld"
            "}",
            exp, iat, nbf);
        json = json_loads(jsonbuf, 0, NULL);
        ck_assert_ptr_ne(json, NULL);
        // feature to check out from the 'features' list in the json above
        requested_feature_existant = "Feature1";
        status = _encode_json(json, &jwt_token);
        ck_assert_int_eq(status, MFL_SUCCESS);
        setenv("MODELON_LICENSE_USER_JWT", jwt_token, 1);
        expected_error_message_start = "error: claim 'format_version': actual "
                                       "value does not match expected value:";
        status = mfl_jwt_component_license_check(requested_feature_existant,
                                                 licensed_users_existant,
                                                 error_msg_buffer);
        ck_assert_int_eq(status, MFL_ERROR);
        ck_assert_ptr_ne(error_msg_buffer, NULL);
        actual_error_message_start =
            strndup(error_msg_buffer, strlen(expected_error_message_start));
        ck_assert_str_eq(actual_error_message_start,
                         expected_error_message_start);
        free(actual_error_message_start);
    }

    // test "error: jwt validation failed"
    {
        char error_msg_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
        char jsonbuf[1024];
        json_t *json;
        char *requested_feature_existant;
        char *jwt_token;
        const char *expected_error_message_start;
        char *actual_error_message_start;
        time_t nbf_equal_to_exp;
        mfl_jwt_unsetenv_any_jwt_env_var();
        nbf_equal_to_exp =
            exp; // <--- This causes the error we are looking for, because here
                 // nbf > now, but the requirement is that nbf < now < exp
        // Keep json alphabetically sorted and no newlines for easy comparison.
        sprintf(jsonbuf,
                "{"
                // expiration time
                "\"exp\":%ld,"
                "\"features\":["
                "\"Feature1\","
                "\"Feature2\""
                "],"
                "\"format_version\":\"1.0.0\","
                // issued at (unused by jwt_validate())
                "\"iat\":%ld,"
                // not before
                "\"nbf\":%ld"
                "}",
                exp, iat, nbf_equal_to_exp);
        json = json_loads(jsonbuf, 0, NULL);
        ck_assert_ptr_ne(json, NULL);
        // feature to check out from the 'features' list in the json above
        requested_feature_existant = "Feature1";
        status = _encode_json(json, &jwt_token);
        ck_assert_int_eq(status, MFL_SUCCESS);
        setenv("MODELON_LICENSE_USER_JWT", jwt_token, 1);
        expected_error_message_start = "error: jwt validation failed: status:";
        status = mfl_jwt_component_license_check(requested_feature_existant,
                                                 licensed_users_existant,
                                                 error_msg_buffer);
        ck_assert_int_eq(status, MFL_ERROR);
        ck_assert_ptr_ne(error_msg_buffer, NULL);
        actual_error_message_start =
            strndup(error_msg_buffer, strlen(expected_error_message_start));
        ck_assert_str_eq(actual_error_message_start,
                         expected_error_message_start);
        free(actual_error_message_start);
    }

    // test "error: jwt does not contain claim: features"
    {
        char error_msg_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
        char jsonbuf[1024];
        json_t *json;
        char *requested_feature_existant;
        char *jwt_token;
        const char *expected_error_message_start;
        char *actual_error_message_start;
        mfl_jwt_unsetenv_any_jwt_env_var();
        // Keep json alphabetically sorted and no newlines for easy comparison.
        sprintf(jsonbuf,
                "{"
                // expiration time
                "\"exp\":%ld,"
                "\"format_version\":\"1.0.0\","
                // issued at (unused by jwt_validate())
                "\"iat\":%ld,"
                // not before
                "\"nbf\":%ld"
                "}",
                exp, iat, nbf);
        json = json_loads(jsonbuf, 0, NULL);
        ck_assert_ptr_ne(json, NULL);
        // feature to check out -- the key 'features' does not exist in the json
        // above
        requested_feature_existant = "Feature1";
        status = _encode_json(json, &jwt_token);
        ck_assert_int_eq(status, MFL_SUCCESS);
        setenv("MODELON_LICENSE_USER_JWT", jwt_token, 1);
        expected_error_message_start =
            "error: jwt does not contain claim: features";
        status = mfl_jwt_component_license_check(requested_feature_existant,
                                                 licensed_users_existant,
                                                 error_msg_buffer);
        ck_assert_int_eq(status, MFL_ERROR);
        ck_assert_ptr_ne(error_msg_buffer, NULL);
        actual_error_message_start =
            strndup(error_msg_buffer, strlen(expected_error_message_start));
        ck_assert_str_eq(actual_error_message_start,
                         expected_error_message_start);
        free(actual_error_message_start);
    }

    // test "error: failed to load json"
    {
        char error_msg_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
        char jsonbuf[1024];
        json_t *json;
        char *requested_feature_existant;
        char *jwt_token;
        const char *expected_error_message_start;
        char *actual_error_message_start;
        mfl_jwt_unsetenv_any_jwt_env_var();
        // Keep json alphabetically sorted and no newlines for easy comparison.
        sprintf(
            jsonbuf,
            "{"
            // expiration time
            "\"exp\":%ld,"
            "\"features\":\"Feature1\"," // <--- not a json array but a string
            "\"format_version\":\"1.0.0\","
            // issued at (unused by jwt_validate())
            "\"iat\":%ld,"
            // not before
            "\"nbf\":%ld"
            "}",
            exp, iat, nbf);
        json = json_loads(jsonbuf, 0, NULL);
        ck_assert_ptr_ne(json, NULL);
        // feature to check out -- the value of the key 'features' in the json
        // above
        requested_feature_existant = "Feature1";
        status = _encode_json(json, &jwt_token);
        ck_assert_int_eq(status, MFL_SUCCESS);
        setenv("MODELON_LICENSE_USER_JWT", jwt_token, 1);
        expected_error_message_start =
            "error: failed to load json: jwt claim 'features' json input:\n";
        status = mfl_jwt_component_license_check(requested_feature_existant,
                                                 licensed_users_existant,
                                                 error_msg_buffer);
        ck_assert_int_eq(status, MFL_ERROR);
        ck_assert_ptr_ne(error_msg_buffer, NULL);
        actual_error_message_start =
            strndup(error_msg_buffer, strlen(expected_error_message_start));
        ck_assert_str_eq(actual_error_message_start,
                         expected_error_message_start);
        free(actual_error_message_start);
    }

    // test "error: not a json array";
    {
        char error_msg_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
        char jsonbuf[1024];
        json_t *json;
        char *requested_feature_nonexistant;
        char *jwt_token;
        const char *expected_error_message_start;
        char *actual_error_message_start;
        mfl_jwt_unsetenv_any_jwt_env_var();
        // Keep json alphabetically sorted and no newlines for easy comparison.
        sprintf(jsonbuf,
                "{"
                // expiration time
                "\"exp\":%ld,"
                "\"features\":{}," // <--- not a json array but an (empty) json
                                   // object
                "\"format_version\":\"1.0.0\","
                // issued at (unused by jwt_validate())
                "\"iat\":%ld,"
                // not before
                "\"nbf\":%ld"
                "}",
                exp, iat, nbf);
        json = json_loads(jsonbuf, 0, NULL);
        ck_assert_ptr_ne(json, NULL);
        // feature to check out -- does not exist in 'features' in the json
        // above
        requested_feature_nonexistant = "Feature1";
        status = _encode_json(json, &jwt_token);
        ck_assert_int_eq(status, MFL_SUCCESS);
        setenv("MODELON_LICENSE_USER_JWT", jwt_token, 1);
        expected_error_message_start =
            "error: not a json array: jwt claim 'features' json input:\n";
        status = mfl_jwt_component_license_check(requested_feature_nonexistant,
                                                 licensed_users_existant,
                                                 error_msg_buffer);
        ck_assert_int_eq(status, MFL_ERROR);
        ck_assert_ptr_ne(error_msg_buffer, NULL);
        actual_error_message_start =
            strndup(error_msg_buffer, strlen(expected_error_message_start));
        ck_assert_str_eq(actual_error_message_start,
                         expected_error_message_start);
        free(actual_error_message_start);
    }

    // test "error: not a json string: value:"
    {
        char error_msg_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
        char jsonbuf[1024];
        json_t *json;
        char *requested_feature_existant;
        char *jwt_token;
        const char *expected_error_message_start;
        char *actual_error_message_start;
        mfl_jwt_unsetenv_any_jwt_env_var();
        // Keep json alphabetically sorted and no newlines for easy comparison.
        sprintf(jsonbuf,
                "{"
                // expiration time
                "\"exp\":%ld,"
                "\"features\":["
                "\"Feature1\","
                "12345," // <---- not a json string value, an integer
                "\"Feature3\""
                "],"
                "\"format_version\":\"1.0.0\","
                // issued at (unused by jwt_validate())
                "\"iat\":%ld,"
                // not before
                "\"nbf\":%ld"
                "}",
                exp, iat, nbf);
        json = json_loads(jsonbuf, 0, NULL);
        ck_assert_ptr_ne(json, NULL);
        // feature to check out from the 'features' list in the json above
        requested_feature_existant = "Feature3";
        status = _encode_json(json, &jwt_token);
        ck_assert_int_eq(status, MFL_SUCCESS);
        setenv("MODELON_LICENSE_USER_JWT", jwt_token, 1);
        expected_error_message_start = "error: not a json string: value:";
        status = mfl_jwt_component_license_check(requested_feature_existant,
                                                 licensed_users_existant,
                                                 error_msg_buffer);
        ck_assert_int_eq(status, MFL_ERROR);
        ck_assert_ptr_ne(error_msg_buffer, NULL);
        actual_error_message_start =
            strndup(error_msg_buffer, strlen(expected_error_message_start));
        ck_assert_str_eq(actual_error_message_start,
                         expected_error_message_start);
        free(actual_error_message_start);
    }

    // test "error: requested feature not found in jwt claim 'features'"
    {
        char error_msg_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
        char jsonbuf[1024];
        json_t *json;
        char *requested_feature_nonexistant = NULL;
        char *jwt_token;
        const char *expected_error_message_start;
        char *actual_error_message_start;
        mfl_jwt_unsetenv_any_jwt_env_var();
        // Keep json alphabetically sorted and no newlines for easy comparison.
        sprintf(jsonbuf,
                "{"
                // expiration time
                "\"exp\":%ld,"
                "\"features\":["
                "\"Feature1\","
                "\"Feature2\""
                "],"
                "\"format_version\":\"1.0.0\","
                // issued at (unused by jwt_validate())
                "\"iat\":%ld,"
                // not before
                "\"nbf\":%ld"
                "}",
                exp, iat, nbf);
        json = json_loads(jsonbuf, 0, NULL);
        ck_assert_ptr_ne(json, NULL);
        // feature to check out that does not exist in the 'features' list in
        // the json above
        requested_feature_nonexistant = "NonExistantFeature";
        status = _encode_json(json, &jwt_token);
        ck_assert_int_eq(status, MFL_SUCCESS);
        setenv("MODELON_LICENSE_USER_JWT", jwt_token, 1);
        expected_error_message_start =
            "error: requested feature not found in jwt claim 'features': "
            "requested feature:";
        status = mfl_jwt_component_license_check(requested_feature_nonexistant,
                                                 licensed_users_existant,
                                                 error_msg_buffer);
        ck_assert_int_eq(status, MFL_ERROR);
        ck_assert_ptr_ne(error_msg_buffer, NULL);
        actual_error_message_start =
            strndup(error_msg_buffer, strlen(expected_error_message_start));
        ck_assert_str_eq(actual_error_message_start,
                         expected_error_message_start);
        free(actual_error_message_start);
    }

    // test "error: User '%s' is not licensed to use this library."
    {
        char error_msg_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
        char jsonbuf[1024];
        json_t *json;
        char *jwt_token;
        const char *expected_error_message_start;
        char *actual_error_message_start;
        mfl_jwt_unsetenv_any_jwt_env_var();
        // Keep json alphabetically sorted and no newlines for easy comparison.
        sprintf(
            jsonbuf,
            "{"
            // expiration time
            "\"exp\":%ld,"
            "\"features\":["
            "\"Feature1\","
            "\"Feature2\""
            "],"
            "\"format_version\":\"1.0.0\","
            // issued at (unused by jwt_validate())
            "\"iat\":%ld,"
            // not before
            "\"nbf\":%ld,"
            "\"user\": {"
            "\"id\": \"example-id\","
            "\"username\": \"notlicensed.user@example.com\"" // <--- this user
                                                             // is not licensed
                                                             // to use this
                                                             // library
            "}"
            "}",
            exp, iat, nbf);
        json = json_loads(jsonbuf, 0, NULL);
        ck_assert_ptr_ne(json, NULL);
        status = _encode_json(json, &jwt_token);
        ck_assert_int_eq(status, MFL_SUCCESS);
        setenv("MODELON_LICENSE_USER_JWT", jwt_token, 1);
        expected_error_message_start =
            "error: User 'notlicensed.user@example.com' is not licensed to use "
            "this library.The users that are licensed to use this library "
            "are:\nexample.email@example.com";
        status = mfl_jwt_component_license_check(requested_feature_existant,
                                                 licensed_users_existant,
                                                 error_msg_buffer);
        ck_assert_int_eq(status, MFL_ERROR);
        ck_assert_ptr_ne(error_msg_buffer, NULL);
        actual_error_message_start =
            strndup(error_msg_buffer, strlen(expected_error_message_start));
        ck_assert_str_eq(actual_error_message_start,
                         expected_error_message_start);
        free(actual_error_message_start);
    }

    mfl_jwt_unsetenv_any_jwt_env_var();
}
END_TEST

START_TEST(test_mfl_jwt_check_any_jwt_env_var_set)
{
    int status = 0;
    mfl_jwt_unsetenv_any_jwt_env_var();

    status = mfl_jwt_check_any_jwt_env_var_set();
    ck_assert_int_eq(status, MFL_ERROR);

    setenv("MODELON_LICENSE_USER_JWT", "This is a test", 1);
    status = mfl_jwt_check_any_jwt_env_var_set();
    ck_assert_int_eq(status, MFL_SUCCESS);
    unsetenv("MODELON_LICENSE_USER_JWT");

    status = mfl_jwt_check_any_jwt_env_var_set();
    ck_assert_int_eq(status, MFL_ERROR);

    setenv("MODELON_LICENSE_USER_JWT_URL", "This is a test", 1);
    status = mfl_jwt_check_any_jwt_env_var_set();
    ck_assert_int_eq(status, MFL_SUCCESS);
    unsetenv("MODELON_LICENSE_USER_JWT_URL");

    mfl_jwt_unsetenv_any_jwt_env_var();
}
END_TEST

START_TEST(test_mfl_jwt_ssl_util_get_timeout)
{
    int status;
    // test default timeout
    {
        long actual_default_timeout;
        char error_msg_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
        status = mfl_jwt_ssl_util_get_timeout(&actual_default_timeout,
                                              error_msg_buffer);
        ck_assert_int_eq(status, MFL_SUCCESS);
        ck_assert_int_eq(
            actual_default_timeout,
            MODELON_LICENSE_USER_JWT_URL_CONNECTION_TIMEOUT_DEFAULT);
    }

    // test timeout set by environment variable
    // MODELON_LICENSE_USER_JWT_URL_CONNECTION_TIMEOUT
    {
        long actual_env_timeout;
        char error_msg_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
        setenv("MODELON_LICENSE_USER_JWT_URL_CONNECTION_TIMEOUT", "1234", 1);
        status =
            mfl_jwt_ssl_util_get_timeout(&actual_env_timeout, error_msg_buffer);
        ck_assert_int_eq(status, MFL_SUCCESS);
        ck_assert_int_eq(actual_env_timeout, 1234L);
        unsetenv("MODELON_LICENSE_USER_JWT_URL_CONNECTION_TIMEOUT");
    }

    // test timeout set by environment variable
    // MODELON_LICENSE_USER_JWT_URL_CONNECTION_TIMEOUT -- should fail when not
    // an int
    {
        long actual_invalid_env_timeout;
        const char *expected_error_message_start =
            "error: environment variable value could not be parsed:";
        char error_msg_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
        setenv("MODELON_LICENSE_USER_JWT_URL_CONNECTION_TIMEOUT", "not_an_int",
               1);
        status = mfl_jwt_ssl_util_get_timeout(&actual_invalid_env_timeout,
                                              error_msg_buffer);
        ck_assert_int_eq(status, MFL_ERROR);
        ck_assert_ptr_ne(error_msg_buffer, NULL);
        ck_assert_str_eq(
            strndup(error_msg_buffer, strlen(expected_error_message_start)),
            expected_error_message_start);
        unsetenv("MODELON_LICENSE_USER_JWT_URL_CONNECTION_TIMEOUT");
    }
}
END_TEST

// ---------------------------------------------------------------------------
Suite *mfl_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("MFL_suite");
    tc_core = tcase_create("Core");

#ifndef WIN32
    tcase_add_test(tc_core, test_mfl_jwt_checkout_checkin);
    tcase_add_test(tc_core, test_mfl_jwt_check_any_jwt_env_var_set);
    tcase_add_test(tc_core, test_mfl_jwt_ssl_util_get_timeout);
#endif

    suite_add_tcase(s, tc_core);

    return s;
}

// -----------------------------------------------------------------------

int run_test_suite(Suite *(get_test_suite)(void))
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = get_test_suite();

    sr = srunner_create(s);
    srunner_set_xml(sr, TEST_REPORT_FN);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    fflush(NULL);
    srunner_free(sr);

    return number_failed;
}

#define COMMAND_OK 0
#define COMMAND_ERROR 1

void display_usage(const char *);

int main(int argc, char **argv) { return run_test_suite(mfl_suite); }
