
#include "DynTrace.h"
#include "JCovPCG_DynTrace.h"

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Class:     JCovPCG_DynTrace
 * Method:    JvTrace
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_JCovPCG_DynTrace_JvTrace (JNIEnv *env, jclass jc, jint BlockID)
{
    DynTracePCG (BlockID);
    return;
}

/*
 * Class:     JCovPCG_DynTrace
 * Method:    JvTraceD8
 * Signature: (IIC)V
 */
JNIEXPORT void JNICALL Java_JCovPCG_DynTrace_JvTraceD8 (JNIEnv *env, jclass jc, jint BlockID, jint ValKey, jchar Value)
{
    DynTraceD8(BlockID, ValKey, Value);
    return;
}

/*
 * Class:     JCovPCG_DynTrace
 * Method:    JvTraceD16
 * Signature: (IIS)V
 */
JNIEXPORT void JNICALL Java_JCovPCG_DynTrace_JvTraceD16 (JNIEnv *env, jclass jc, jint BlockID, jint ValKey, jshort Value)
{
    DynTraceD16(BlockID, ValKey, Value);
    return;
}

/*
 * Class:     JCovPCG_DynTrace
 * Method:    JvTraceD32
 * Signature: (III)V
 */
JNIEXPORT void JNICALL Java_JCovPCG_DynTrace_JvTraceD32 (JNIEnv *env, jclass jc, jint BlockID, jint ValKey, jint Value)
{
    DynTraceD32(BlockID, ValKey, Value);
    return;
}

/*
 * Class:     JCovPCG_DynTrace
 * Method:    JvTraceD64
 * Signature: (IIJ)V
 */
JNIEXPORT void JNICALL Java_JCovPCG_DynTrace_JvTraceD64 (JNIEnv *env, jclass jc, jint BlockID, jint ValKey, jlong Value)
{
    DynTraceD64(BlockID, ValKey, Value);
    return;
}


/*
 * Class:     JCovPCG_DynTrace
 * Method:    JvTraceInit
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_JCovPCG_DynTrace_JvTraceInit (JNIEnv *env, jclass jc, jint blockNum)
{
    unsigned BBs = blockNum;
    DynTraceInit (BBs);
    return;
}

/*
* Class:     JCovPCG_DynTrace
* Method:    JvTraceDeInit
* Signature: (I)V
*/
JNIEXPORT void JNICALL Java_JCovPCG_DynTrace_JvTraceDeInit (JNIEnv *env, jclass jc, jint exitCode)
{
    /* exit anyway */
    exit (exitCode);
}


#ifdef __cplusplus
}
#endif




