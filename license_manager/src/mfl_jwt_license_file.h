/*
 * Copyright (C) 2022 Modelon AB
 */
#ifndef MFL_jwt_license_file_H_
#define MFL_jwt_license_file_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @param licensed_users contains the licensed users from the license file
 * separated by '\n'
 * @return MFL_SUCCESS on success, or MFL_ERROR on failure. licensed_users.
 * Caller must free() licensed_users.
 */
int mfl_jwt_license_file_get_licensed_users(char **licensed_users,
                                            char *libpath,
                                            char *error_msg_buffer);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MFL_jwt_license_file_H_ */
