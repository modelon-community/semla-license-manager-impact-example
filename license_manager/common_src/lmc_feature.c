/* 
 * Copyright (C) 2022 Modelon AB
 */
#include "lmc_feature.h"

#include <stdlib.h>
#include <string.h>

#include <stdio.h>


static int
copy(char **dest, const char *start, const char *end);


#define SEP '|'

#define DEFAULT_VERSION_LEN 3
static char DEFAULT_VERSION[DEFAULT_VERSION_LEN+1] = "1.0";
#define DEFAULT_NLICENCES 1

int
unmarshal_feature(const char *blob,
                  size_t blob_length,
                  char **feature,
                  char **version,
                  unsigned int *nlicenses)
{
    struct substr {
        const char *start;
        const char *end;
    };
    struct substr s[3];
    unsigned int si = 0;
    const char *from;
    const char *to;
    char *num = NULL;
    int result = 0;

    if (feature) {
        *feature = NULL;
    }

    if (version) {
        *version = NULL;
    }

    from = blob;
    while (from && si < 3) {
        to = strchr(from, SEP);

        s[si].start = from;

        if (to == NULL) {
            s[si].end = blob + blob_length - 1;
            break;
        } else {
            s[si].end = to - 1;
            from = to + 1;
            si += 1;
        }
    }

    switch (si) {
        case 3:
        case 2:
            if (nlicenses) {
                if (!copy(&num, s[2].start, s[2].end)) {
                    goto error;
                }
                if (num) {
                    *nlicenses = atoi(num);
                }
            }
        case 1:
            if (!copy(version, s[1].start, s[1].end)) {
                goto error;
            }
        case 0:
            if (!copy(feature, s[0].start, s[0].end)) {
                goto error;
            }
            break;
        default:
        /* Can't happen */
            goto error;
            break;
    }
    if (nlicenses && !num) {
        *nlicenses = DEFAULT_NLICENCES;
    }
    if (version && !*version) {
        if (!copy(version, DEFAULT_VERSION, DEFAULT_VERSION + DEFAULT_VERSION_LEN - 1)) {
            goto error;
        }
    }

    result = 1;
error:
    if (num) { free(num); }

    if (!result) {
        if (version && *version) { free(*version); }
        if (feature && *feature) { free(*feature); }
    }

    return result;
}


static int
copy(char **dest, const char *start, const char *end)
{
    size_t length = end - start + 1;
    int result = 0;
    
    /* If the destination is invalid or if the input represents
     * the empty string, then return NULL.
     */
    if (dest == NULL || length == 0) {
        result = 1; /* This is not an error */
        goto error;
    }
    
    *dest = malloc(length + 1);
    if (*dest == NULL) {
        goto error;
    }
    
    memcpy(*dest, start, length);
    (*dest)[length] = '\0';
    
    result = 1;
error:
    return result;
}
