/* 
 * Copyright (C) 2022 Modelon AB
 */
#ifndef MFL_jwt_license_file_decrypt_file_H_
#define MFL_jwt_license_file_decrypt_file_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @param error_msg_buffer error message buffer
 * @param libpath path to the library
 * @param license_file_relative_path relative path to the license file
 * @param encrypted_license_file_contents contents of the license file
 * @param encrypted_license_file_contents_sz size of contents of the license
 * file
 * @param decrypted_license_file_contents decrypted contents of the license file
 * @return MFL_SUCCESS on success, or MFL_ERROR on failure.
 * decrypted_license_file_contents. Caller must free()
 * decrypted_license_file_contents.
 */
int mfl_jwt_license_file_decrypt_file(char *error_msg_buffer, char *libpath,
                                      char *license_file_relative_path,
                                      char *encrypted_license_file_contents,
                                      size_t encrypted_license_file_contents_sz,
                                      char **decrypted_license_file_contents);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MFL_jwt_license_file_decrypt_file_H_ */
