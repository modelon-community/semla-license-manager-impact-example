#define _CRT_SECURE_NO_WARNINGS

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "mlle_license_manager.h"
#include "mlle_portability.h"

#include "lmc_feature.h"

#include "mfl_interface.h"

struct mlle_license {
    mfl_license_t *mfl;
};

struct mlle_license*
mlle_license_new(const char *not_used,
                 struct mlle_error **error)
{
        struct mlle_license *mlic = NULL;
		mfl_license_t *mfl = NULL;
		
        if ((mfl = mfl_license_new()) == NULL) {
            mlle_error_set(error, LICENSE_DOMAIN, LICENSE_ERROR_INITIALIZATION_FAILURE,
                "Failed to allocate MFL license");
            goto error;
        }

        if (mfl_initialize(mfl) == MFL_ERROR) {
            mlle_error_set(error, LICENSE_DOMAIN, LICENSE_ERROR_INITIALIZATION_FAILURE,
                "Failed to initialize MFL license interface");
            goto error;
        }

        if ((mlic = calloc(1, sizeof(struct mlle_license))) == NULL) {
            mlle_error_set(error, LICENSE_DOMAIN, LICENSE_ERROR_INTERNAL,
                "Out of memory");
            goto error;
        }
		
		mlic->mfl = mfl;
		
        return mlic;

    error:
        if (mfl) {
            mfl_license_free(mfl);
        }

        return NULL;
    }

void
mlle_license_free(struct mlle_license *mlic)
{
    if (mlic) {
        if (mlic->mfl) {
			mfl_license_free(mlic->mfl) ;
        }

        free(mlic);
    }
}
const char* IMPACT_LIBRARIES = "IMPACT_LIBRARIES";
extern FILE* mlle_log;

int
mlle_license_checkout_feature(struct mlle_license *mlic,
                              size_t feature_length,
                              const char *feature,
                              struct mlle_error **error)
{
    int result = MLLE_LIC_FAILURE;
    char *the_feature = NULL;
    char *the_version = NULL;
    unsigned int num_licenses;

    if (!mlic) {
        mlle_error_set(error, LICENSE_DOMAIN, LICENSE_ERROR_INVALID_REFERENCE,
            "Invalid reference");
        goto error;
    }
#define STR2(x) #x
#define STR(x) STR2(x)
#ifdef MLLE_GLOBAL_LICENSE_FEATURE    
    if((strcmp( STR ( MLLE_GLOBAL_LICENSE_FEATURE ) , IMPACT_LIBRARIES) == 0) && strcmp(feature, "test_non_licensed_feature")) {
        feature = IMPACT_LIBRARIES;
        feature_length = strlen(IMPACT_LIBRARIES);
    }
#endif
    if (!unmarshal_feature(feature, feature_length, &the_feature, &the_version,
                        &num_licenses)) {
        mlle_error_set(error, LICENSE_DOMAIN, LICENSE_ERROR_BAD_FEATURE,
            "The feature format is illegal");
        goto error;
    }
    if(mlle_log) {
        fprintf(mlle_log, "Checking out license feature: %s, version: %s\n", the_feature, the_version);
    }
    
	if(mfl_checkout_feature(mlic->mfl, the_feature, the_version, num_licenses) == MFL_ERROR) {
        mlle_error_set(error, LICENSE_DOMAIN, LICENSE_ERROR_CHECKOUT_FAILURE,
            mfl_last_error(mlic->mfl)); //TODO: error can be NULL, code in SEMLA doesn't handle that, a test should trigger this case
        goto error;
    }
    result = MLLE_LIC_SUCCESS;
	
error:

    if (the_version != NULL) {
        free(the_version);
    }

    if (the_feature != NULL) {
        free(the_feature);
    }

    return result;
}

int
mlle_license_checkin_feature(struct mlle_license *mlic,
                             size_t feature_length,
                             const char *feature,
                             struct mlle_error **error)
{
    int result = MLLE_LIC_FAILURE;
    char *the_feature = NULL;

    if (!mlic) {
        mlle_error_set(error, LICENSE_DOMAIN, LICENSE_ERROR_INVALID_REFERENCE,
            "Invalid reference");
        goto error;
    }

    if (!unmarshal_feature(feature, feature_length, &the_feature, NULL, NULL)) {
        mlle_error_set(error, LICENSE_DOMAIN, LICENSE_ERROR_BAD_FEATURE,
            "The feature format is illegal");
        goto error;
    }

	if (mfl_checkin_feature(mlic->mfl, the_feature) == MFL_ERROR) {
        mlle_error_set(error, LICENSE_DOMAIN, LICENSE_ERROR_BAD_FEATURE,
            "Can't check-in feature"); //TODO: error can be NULL, code in SEMLA doesn't handle that, a test should trigger this case
        goto error;
    }
	
    result = MLLE_LIC_SUCCESS;

error:

    if (the_feature != NULL) {
        free(the_feature);
    }

    return result;
}


