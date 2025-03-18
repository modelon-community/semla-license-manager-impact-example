/* 
 * Copyright (C) 2022 Modelon AB
 */
#define _XOPEN_SOURCE 700
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
    char *libpath;

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
static int setup_jwt(mfl_license_t *mfl, char *libpath);

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

int mfl_initialize(mfl_license_t *mfl, const char *libpath)
{
    return setup_jwt(mfl, libpath);
}

int mfl_license_free(mfl_license_t *mfl)
{
    if (!mfl) {
        goto out;
    }

    if (mfl->free) {
        mfl->free(mfl->module_data);
    }

    if (mfl->libpath) {
        free(mfl->libpath);
    }

    free_mfl_error(mfl);

    if (mfl->latest_error != mfl->init_error) {
        free(mfl->latest_error);
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
    char *result = NULL;
    if (mfl && mfl->module_data)
        result = mfl->get_last_error(mfl->module_data);
    else if (mfl) {
        result = mfl->latest_error;
    }
    if (result == NULL) {
        // code in SEMLA doesn't handle when error is NULL 
        result = "";
    }
    return result;
}

static void free_mfl_error(mfl_license_t *mfl) {
    if (mfl && (mfl->latest_error != mfl->init_error)) {
        free(mfl->latest_error);
        mfl->latest_error = mfl->init_error;
    }
}

static int setup_jwt(mfl_license_t *mfl, char *libpath) {
    mfl->module_data      = (mfl_module_data_t *) mfl_jwt_license_new();
    mfl->free             = mfl_jwt_license_free;
    mfl->checkout_feature = mfl_jwt_checkout_feature;
    mfl->checkin_feature  = mfl_jwt_checkin_feature;
    mfl->get_last_error   = mfl_jwt_last_error;

    return mfl_jwt_initialize(mfl->module_data, libpath);
}
