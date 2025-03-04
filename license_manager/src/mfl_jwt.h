#ifndef MFL_jwt_H_
#define MFL_jwt_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define MFL_SUCCESS 1
#define MFL_ERROR   0

#define MFL_JWT_ERROR_MSG_BUFFER_SIZE 8000

typedef struct mfl_license_jwt mfl_license_jwt_t;

mfl_license_jwt_t * mfl_jwt_license_new();

int mfl_jwt_initialize(void *module_data);

void mfl_jwt_license_free(mfl_module_data_t *module_data);

int mfl_jwt_checkout_feature(mfl_module_data_t *module_data,
                                   const char *feature,
                                   const char *version,
                                   int         num_lic);

int mfl_jwt_checkin_feature(mfl_module_data_t *module_data,
                                  const char *feature);

char* mfl_jwt_last_error(mfl_module_data_t *module_data);

int mfl_jwt_check_any_jwt_env_var_set();

/**
 * @brief  Component license check. The license check will pass if the JWT is valid and “features” list contains the requested feature. 
 * @param requested_feature 
 * @param jwt_token 
 * @param error_msg_buffer 
 * @return MFL_SUCCESS if the license check is passed, MFL_ERROR otherwise.
 */
int mfl_jwt_component_license_check(const char *requested_feature, char **jwt_token,
                                    char *error_msg_buffer);

// private
int mfl_jwt_util_asprintf(char *error_msg_buffer, char **strp, const char *fmt, ...);
size_t mfl_jwt_util_read_file(char **out, FILE* fp, char *error_msg_buffer);
int mfl_jwt_unsetenv_any_jwt_env_var(void);
void _print_to_error_msg_buffer(char *error_msg_buffer,
                                       char *error_msg_start);

#define MODELON_LICENSE_USER_JWT_URL_CONNECTION_TIMEOUT_DEFAULT 10L

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MFL_jwt_H_ */
