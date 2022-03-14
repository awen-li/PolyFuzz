/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class JCovPCG_DynTrace */

#ifndef _Included_JCovPCG_DynTrace
#define _Included_JCovPCG_DynTrace
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     JCovPCG_DynTrace
 * Method:    JvTrace
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_JCovPCG_DynTrace_JvTrace
  (JNIEnv *, jclass, jint);

/*
 * Class:     JCovPCG_DynTrace
 * Method:    JvTraceD8
 * Signature: (IIC)V
 */
JNIEXPORT void JNICALL Java_JCovPCG_DynTrace_JvTraceD8
  (JNIEnv *, jclass, jint, jint, jchar);

/*
 * Class:     JCovPCG_DynTrace
 * Method:    JvTraceD16
 * Signature: (IIS)V
 */
JNIEXPORT void JNICALL Java_JCovPCG_DynTrace_JvTraceD16
  (JNIEnv *, jclass, jint, jint, jshort);

/*
 * Class:     JCovPCG_DynTrace
 * Method:    JvTraceD32
 * Signature: (III)V
 */
JNIEXPORT void JNICALL Java_JCovPCG_DynTrace_JvTraceD32
  (JNIEnv *, jclass, jint, jint, jint);

/*
 * Class:     JCovPCG_DynTrace
 * Method:    JvTraceD64
 * Signature: (IIJ)V
 */
JNIEXPORT void JNICALL Java_JCovPCG_DynTrace_JvTraceD64
  (JNIEnv *, jclass, jint, jint, jlong);

/*
 * Class:     JCovPCG_DynTrace
 * Method:    JvTraceInit
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_JCovPCG_DynTrace_JvTraceInit
  (JNIEnv *, jclass, jint);

/*
 * Class:     JCovPCG_DynTrace
 * Method:    JvTraceDeInit
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_JCovPCG_DynTrace_JvTraceDeInit
  (JNIEnv *, jclass, jint);

#ifdef __cplusplus
}
#endif
#endif
