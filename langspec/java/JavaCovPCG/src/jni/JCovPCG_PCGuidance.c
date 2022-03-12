#include <stdbool.h>
#include "pcgInstrm.h"
#include "JCovPCG_PCGuidance.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Class:     JCovPCG_PCGuidance
 * Method:    pcgCFGAlloct
 * Signature: (I)V
 */
JNIEXPORT jint JNICALL Java_JCovPCG_PCGuidance_pcgCFGAlloct (JNIEnv *env, jclass jc, jint entryId)
{
    return pcgCFGAlloct(entryId);
}

/*
 * Class:     JCovPCG_PCGuidance
 * Method:    pcgCFGDel
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_JCovPCG_PCGuidance_pcgCFGDel (JNIEnv *env, jclass jc, jint Handle)
{
    pcgCFGDel (Handle);
}


/*
 * Class:     JCovPCG_PCGuidance
 * Method:    pcgCFGEdge
 * Signature: (III)V
 */
JNIEXPORT void JNICALL Java_JCovPCG_PCGuidance_pcgCFGEdge (JNIEnv *env, jclass jc, jint Handle, jint sId, jint eId)
{
    pcgCFGEdge(Handle, sId, eId);
    return;
}


/*
 * Class:     JCovPCG_PCGuidance
 * Method:    pcgInsertIR
 * Signature: (IILjava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_JCovPCG_PCGuidance_pcgInsertIR (JNIEnv *env, jclass jc, jint Handle, jint BlockId, jstring SaIR)
{
    const char *ntSaIR = (*env)->GetStringUTFChars(env, SaIR, 0);
    pcgInsertIR (Handle, BlockId, ntSaIR);
    (*env)->ReleaseStringUTFChars(env, SaIR, ntSaIR);
    
    return;
}


/*
 * Class:     JCovPCG_PCGuidance
 * Method:    pcgBuild
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_JCovPCG_PCGuidance_pcgBuild (JNIEnv *env, jclass jc, jint Handle)
{
    pcgBuild(Handle);
    return;
}

/*
 * Class:     JCovPCG_PCGuidance
 * Method:    pcgNeedInstrumented
 * Signature: (II)Z
 */
JNIEXPORT jboolean JNICALL Java_JCovPCG_PCGuidance_pcgNeedInstrumented (JNIEnv *env, jclass jc, jint Handle, jint Id)
{
    return pcgNeedInstrumented (Handle, Id);
}


/*
 * Class:     JCovPCG_PCGuidance
 * Method:    pcgIsDominated
 * Signature: (III)Z
 */
JNIEXPORT jboolean JNICALL Java_JCovPCG_PCGuidance_pcgIsDominated (JNIEnv *env, jclass jc, jint Handle, jint dId, jint Id)
{
    return pcgIsDominated(Handle, dId, Id);
}

/*
 * Class:     JCovPCG_PCGuidance
 * Method:    pcgIsPostDominated
 * Signature: (III)Z
 */
JNIEXPORT jboolean JNICALL Java_JCovPCG_PCGuidance_pcgIsPostDominated (JNIEnv *env, jclass jc, jint Handle, jint pdId, jint Id)
{
    return pcgIsPostDominated(Handle, pdId, Id);
}

#ifdef __cplusplus
}
#endif



