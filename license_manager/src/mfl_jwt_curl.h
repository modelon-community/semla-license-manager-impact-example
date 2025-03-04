#ifndef MFL_jwt_curl_H_
#define MFL_jwt_curl_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @param jwt_token contains the jwt token from the server
 * @return MFL_SUCCESS on success, or MFL_ERROR on failure. jwt_token. Caller
 * must free() jwt_token.
 */
int mfl_jwt_url_http_and_https(char **jwt_token, char *error_msg_buffer);

// private

/**
 * @brief Get timeout from the env variable
 * MODELON_LICENSE_USER_JWT_URL_CONNECTION_TIMEOUT
 * @param timeout
 * @return MFL_SUCCESS on success, or MFL_ERROR on failure
 */
int mfl_jwt_ssl_util_get_timeout(long *timeout, char *error_msg_buffer);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MFL_jwt_curl_H_ */
