#ifndef MFL_jwt_license_file_H_
#define MFL_jwt_license_file_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @param required_user contains the required user from the license file
 * @return MFL_SUCCESS on success, or MFL_ERROR on failure. required_user. Caller
 * must free() required_user.
 */
int mfl_jwt_license_file_get_required_user(char **required_user, char *error_msg_buffer);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MFL_jwt_license_file_H_ */
