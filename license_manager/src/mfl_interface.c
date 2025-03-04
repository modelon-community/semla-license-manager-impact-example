#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>

#include "mfl_interface.h"

//#define USE_LOGE // set to get LOGE output
#include "mfl_common.h"

#include "mfl_jwt.h"

typedef void* mfl_module_data_t;

struct mfl_license {
    char *latest_error;
    char init_error[1000];
    char *server_ip;
    char *customer_host_id;
    char *server_rights_id;

    /* Module data for submodules. */
    mfl_module_data_t *module_data;

    /* Function pointers for submodules*/
    void (*free)(mfl_module_data_t*);
    int (*checkin_feature)(mfl_module_data_t*, const char *);
    int (*checkout_feature)(mfl_module_data_t*, const char *, const char *, int);
    char* (*get_last_error)(mfl_module_data_t*);
};

// -------------------------------------------------------------------------
// Private function heads
// -------------------------------------------------------------------------
static void free_mfl_error(mfl_license_t *mfl);
static int setup_jwt(mfl_license_t *mfl);

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------
mfl_license_t * mfl_license_new()
{
    const char * NOINIT = "Not initialized";
    mfl_license_t *mfl_license = (mfl_license_t *)calloc(1, sizeof(mfl_license_t));
    mfl_license->latest_error = mfl_license->init_error;
    memcpy(mfl_license->init_error, NOINIT, strlen(NOINIT));
    return mfl_license;
}

int mfl_initialize(mfl_license_t *mfl)
{
    int status            = MFL_SUCCESS;

    if (mfl_jwt_check_any_jwt_env_var_set() == MFL_SUCCESS) {
        LOGE("*** Using MFL JWT ***\n")
        status = setup_jwt(mfl);
    }
    else {
        LOGE("error: need to set one of the environment variables MODELON_LICENSE_USER_JWT or MODELON_LICENSE_USER_JWT_URL\n")
        status = MFL_ERROR;
    }

out:
    return status;
}

int mfl_license_free(mfl_license_t *mfl)
{
    if (!mfl) {
        goto out;
    }

    if (mfl->free) {
        mfl->free(mfl->module_data);
    }

    free_mfl_error(mfl);

    if (mfl->server_ip) {
        free(mfl->server_ip);
    }

    if (mfl->latest_error != mfl->init_error) {
        free(mfl->latest_error);
    }

    if (mfl->customer_host_id) {
        free(mfl->customer_host_id);
    }

    if (mfl->server_rights_id) {
        free(mfl->server_rights_id);
    }

    free(mfl);

out:
    return MFL_SUCCESS;
}

int mfl_checkout_feature(mfl_license_t *mfl,
                         const char    *feature,
                         const char    *version,
                         int            num_lic)
{
    int status = MFL_SUCCESS;

    if (!mfl || !mfl->checkout_feature) {
        status = MFL_ERROR;
        LOGE("Can't checkout feature, MFL is not initialized\n");
        goto out;
    }

    status =  mfl->checkout_feature(mfl->module_data, feature, version, num_lic);

out:
    return status;
}

int mfl_checkin_feature(mfl_license_t *mfl,
                        const char    *feature)
{
    int status = MFL_SUCCESS;
    if (!mfl || !mfl->checkin_feature) {
        status = MFL_ERROR;
        LOGE("Can't checkin feature, MFL is not initialized\n");
        goto out;
    }

    status = mfl->checkin_feature(mfl->module_data, feature);

out:
    return status;
}

char* mfl_last_error(mfl_license_t *mfl)
{
    if (mfl && mfl->module_data)
        return mfl->get_last_error(mfl->module_data);
    else
        return mfl->latest_error;
}

static void free_mfl_error(mfl_license_t *mfl) {
    if (mfl && (mfl->latest_error != mfl->init_error)) {
        free(mfl->latest_error);
        mfl->latest_error = mfl->init_error;
    }
}

static int setup_jwt(mfl_license_t *mfl) {
    mfl->module_data      = (mfl_module_data_t *) mfl_jwt_license_new();
    mfl->free             = mfl_jwt_license_free;
    mfl->checkout_feature = mfl_jwt_checkout_feature;
    mfl->checkin_feature  = mfl_jwt_checkin_feature;
    mfl->get_last_error   = mfl_jwt_last_error;

    return mfl_jwt_initialize(mfl->module_data);
}
