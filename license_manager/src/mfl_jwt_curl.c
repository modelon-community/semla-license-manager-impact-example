/*
 * Copyright (C) 2022 - 2025 Modelon AB
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <curl/curl.h>

#include "mfl_common.h"
#include "mfl_interface.h"
#include "mfl_jwt.h"
#include "mfl_jwt_curl.h"

/* 
* Derived from https://github.com/curl/curl/blob/ad9bc5976d6661cd5b03ebc379313bf657701c14/docs/examples/getinmemory.c 
* Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
* Curl License: https://curl.se/docs/copyright.html 
*/

typedef struct MemoryStruct {
    char *memory;
    size_t size;
} MemoryStruct;

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb,
                                void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) {
        /* out of memory! */
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}


/**
 *  @return MFL_SUCCESS on success, or MFL_ERROR on failure
 */
static int make_request(char *url, MemoryStruct *chunk, char *error_msg_buffer)
{
    int result = MFL_ERROR;
    int status = MFL_ERROR;
    CURL *curl_handle = NULL;
    CURLcode res;
    struct curl_slist *list = NULL;
    const char *MFL_SSL_NO_VERIFY = getenv("MFL_SSL_NO_VERIFY");
    long timeout;
    #define HEADER_BUFFER 10000
    char header_buffer[HEADER_BUFFER];

    status = mfl_jwt_ssl_util_get_timeout(&timeout, error_msg_buffer);
    if (status != MFL_SUCCESS) {
        result = status;
        goto error;
    }
    curl_global_init(CURL_GLOBAL_ALL);

    /* init the curl session */
    curl_handle = curl_easy_init();

    /* specify URL to get */
    curl_easy_setopt(curl_handle, CURLOPT_URL, url);

    /* set timeout */
    curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, timeout);

    /* send all data to this function  */
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)chunk);

    /* some servers do not like requests that are made without a user-agent
    field, so we provide one */
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

    /* form and add authz header */
    snprintf(header_buffer,HEADER_BUFFER, "%s: %s",
        getenv("MODELON_LICENSE_HTTP_CREDENTIAL_HEADER"),
        getenv("MODELON_LICENSE_HTTP_CREDENTIAL_VALUE")
    );

    /* add this header */
    list = curl_slist_append(list, header_buffer);
    
    curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, list);

    /* do not verify the server's SSL certificate if the environment variable
    MFL_SSL_NO_VERIFY is set. workaround for using self-signed certificates
    without loading them into curl. using this when testing https url by
    setting the variable MFL_SSL_NO_VERIFY=1
    */
    if (MFL_SSL_NO_VERIFY != NULL && strcmp(MFL_SSL_NO_VERIFY, "1") == 0) {
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    /* get it! */
    res = curl_easy_perform(curl_handle);

    /* check for errors */
    if (res != CURLE_OK) {
        const char *error_msg_start = NULL;
        char error_msg_input_buffer[MFL_JWT_ERROR_MSG_BUFFER_SIZE];
        size_t error_msg_input_buffer_sz = MFL_JWT_ERROR_MSG_BUFFER_SIZE;
        memset(error_msg_input_buffer, '\0', error_msg_input_buffer_sz);
        error_msg_start = "curl call failed: %s";
        snprintf(error_msg_input_buffer, error_msg_input_buffer_sz,
                error_msg_start, curl_easy_strerror(res));
        _print_to_error_msg_buffer(error_msg_buffer, error_msg_input_buffer);
        goto error;
    }

    /*
    * Now, our chunk->memory points to a memory block that is chunk->size
    * bytes big and contains the remote file.
    *
    * Do something nice with it!
    */
    result = MFL_SUCCESS;

error:

    /* cleanup curl stuff */
    curl_easy_cleanup(curl_handle);

    /* free the headers list */
    curl_slist_free_all(list); 

    /* we are done with libcurl, so clean it up */
    curl_global_cleanup();

    return result;
}

int mfl_jwt_url_http_and_https(char **jwt_token, char *error_msg_buffer)
{
    int result = MFL_ERROR;
    int status = MFL_ERROR;
    char *url;
    MemoryStruct chunk;

    url = getenv("MODELON_LICENSE_USER_JWT_URL");
    if (url == NULL) {
        _print_to_error_msg_buffer(
            error_msg_buffer,
            "error: environment variable not set: MODELON_LICENSE_USER_JWT_URL");
        goto error2;
    }
    chunk.memory = malloc(1); /* will be grown as needed by the realloc() in
                                WriteMemoryCallback() */
    if (chunk.memory == NULL) {
        goto error;
    }
    chunk.size = 0; /* no data at this point */
    status = make_request(url, &chunk, error_msg_buffer);
    if (status != MFL_SUCCESS) {
        result = status;
        goto error;
    }

    /* Copy JWT Token from HTTP response message chunk.memory to a
    * null-terminated string*/
    *jwt_token = malloc((chunk.size + 1) * sizeof(**jwt_token));
    if (*jwt_token == NULL) {
        goto error;
    }
    memcpy(*jwt_token, chunk.memory, chunk.size);
    (*jwt_token)[chunk.size] = '\0';
    result = MFL_SUCCESS;
error:
    free(chunk.memory);
error2:
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