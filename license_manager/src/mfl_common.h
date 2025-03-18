/* 
 * Copyright (C) 2022 Modelon AB
 */
#ifndef MFL_COMMON_H_
#define MFL_COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
#include <stdio.h>

#define MFL_SUCCESS 1
#define MFL_ERROR   0

//#define DEBUG 1

#ifdef USE_LOGE
	#define LOGE(...) fprintf( stderr,"%s: ",__func__);fprintf( stderr, __VA_ARGS__);
#else
    #define LOGE(...)
#endif

#ifdef DEBUG
    #define LOGD(...) fprintf( stderr,"%s: ",__func__);fprintf( stderr, __VA_ARGS__);
#else
    #define LOGD(...)
#endif

#ifdef WIN32
    #define __func__ __FUNCTION__
#endif


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MFL_COMMON_H_ */
