/* 
 * Copyright (C) 2022 Modelon AB
 */
#ifndef MFL_jwt_license_file_H_
#define MFL_jwt_license_file_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @param required_usernames contains the required user from the license file separated by '\n'
 * @return MFL_SUCCESS on success, or MFL_ERROR on failure. required_usernames. Caller
 * must free() required_usernames.
 */
int mfl_jwt_license_file_get_required_usernames(char **required_usernames,
                                                char *libpath,
                                                char *error_msg_buffer);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MFL_jwt_license_file_H_ */
