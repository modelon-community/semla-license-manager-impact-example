/* 
 * Copyright (C) 2022 Modelon AB
 * 
 * NOTE: Thirdparty dependency on OpenSSL, add attribution, see https://www.openssl.org/source/license.html
 * Platform-specific dependencies of OpenSSL need to be dynamically linked. On linux, these are 'dl' and 'pthread'
 * 
 * NOTE: Thirdparty dependency on curl, add attribution, see https://curl.se/docs/copyright.html
 */


#ifndef MFL_INTERFACE_H_
#define MFL_INTERFACE_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Return status values from mfl_initialize and mfl_checkout*/
#ifndef MFL_SUCCESS
#define MFL_SUCCESS 1
#define MFL_ERROR   0
#endif

typedef void* mfl_module_data_t;
typedef struct mfl_license mfl_license_t;

/* Allocate memory for MFL */
mfl_license_t * mfl_license_new();

/* Initialize licensing object */
int mfl_initialize(mfl_license_t *mfl);

/* Releaser allocated resources */
int mfl_license_free(mfl_license_t *mfl);

/* Checkout "num_lic" instances of "feature" with "version" */
int mfl_checkout_feature(mfl_license_t *mfl,
                         const char *feature,
                         const char *version,
                         int num_lic);

/* Checkin previously checked out feature */
int mfl_checkin_feature(mfl_license_t *mfl,
                        const char *feature);

/* Get message reporting licensing error in case MFL_ERROR was returned */
char* mfl_last_error(mfl_license_t *mfl);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MFL_INTERFACE_H_ */
