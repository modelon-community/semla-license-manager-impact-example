#ifndef UNIT_TEST_UTIL_H_
#define UNIT_TEST_UTIL_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

// https://stackoverflow.com/q/7387687
#define STRINGIFY_HIDDEN(x) #x
#define STRINGIFY(x) STRINGIFY_HIDDEN(x)
#define FILE_LINE_STRING (__FILE__ ":" STRINGIFY(__LINE__))

#define UNIT_TEST_PUBLIC_KEY_JWT_KEY_INDEX 0

int read_kid_from_public_keys_jwt_key_id_txt_file(char **kid);
int read_jwt_private_key_from_jwt_key_dir(char **jwt_key, size_t *jwt_key_sz);
int read_jwt_public_key_from_jwt_key_dir(char **jwt_key, size_t *jwt_key_sz);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* UNIT_TEST_UTIL_H_ */
