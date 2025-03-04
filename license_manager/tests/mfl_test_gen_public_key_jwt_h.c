#include <stdio.h>
#include <string.h>

#include "unit_test_util.h"

#include "mfl_common.h"

#include "public_key_jwt.h"

int main(int argc, char** argv)
{
    // check that the expected public key is built into the test executable when running the build system

    char *expected_jwt_key_pub;
    size_t expected_jwt_key_pub_sz;
    char* expected_kid;
    read_jwt_public_key_from_jwt_key_dir(&expected_jwt_key_pub, &expected_jwt_key_pub_sz);
    read_kid_from_public_keys_jwt_key_id_txt_file(&expected_kid);
    int i = 0;
    DECLARE_PUBLIC_KEY_JWT();
    DECLARE_PUBLIC_KEY_JWT_LEN();
    if (PUBLIC_KEY_JWT_NUM < 1)
    {
        return 1;
    }
    if(i >= PUBLIC_KEY_JWT_NUM)
    {
        return 1;
    }
    INITIALIZE_PUBLIC_KEY_JWT();
    if (PUBLIC_KEY_JWT_LEN[i] != strlen(expected_jwt_key_pub))
    {
        return 1;
    }
    if (strcmp(PUBLIC_KEY_JWT[i], expected_jwt_key_pub) != 0)
    {
        return 1;
    }
    DECLARE_PUBLIC_KEY_JWT_KEY_ID();
    if (strcmp(PUBLIC_KEY_JWT_KEY_ID[i], expected_kid) != 0)
    {
        return 1;
    }
    CLEAR_PUBLIC_KEY_JWT();
    return 0;
}