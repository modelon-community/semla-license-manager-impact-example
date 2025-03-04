#ifndef LMC_FEATURE_H_
#define LMC_FEATURE_H_
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int
unmarshal_feature(const char *blob,
                  size_t blob_length,
                  char **feature,
                  char **version,
                  unsigned int *nlicenses);


#ifdef __cplusplus
}
#endif

#endif /* LMC_FEATURE_H_ */