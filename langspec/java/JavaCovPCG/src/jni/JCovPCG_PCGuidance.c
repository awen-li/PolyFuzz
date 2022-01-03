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
JNIEXPORT void JNICALL Java_JCovPCG_PCGuidance_pcgCFGAlloct (JNIEnv *env, jclass jc, jint entryId)
{
    pcgCFGAlloct(entryId);
    return;
}

/*
 * Class:     JCovPCG_PCGuidance
 * Method:    pcgCFGEdge
 * Signature: (II)V
 */
JNIEXPORT void JNICALL Java_JCovPCG_PCGuidance_pcgCFGEdge (JNIEnv *env, jclass jc, jint sId, jint eId)
{
    pcgCFGEdge(sId, eId);
    return;
}

/*
 * Class:     JCovPCG_PCGuidance
 * Method:    pcgBuild
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_JCovPCG_PCGuidance_pcgBuild (JNIEnv *env, jclass jc)
{
    pcgBuild();
    return;
}

/*
 * Class:     JCovPCG_PCGuidance
 * Method:    pcgIsDominated
 * Signature: (II)Z
 */
JNIEXPORT jboolean JNICALL Java_JCovPCG_PCGuidance_pcgIsDominated (JNIEnv *env, jclass jc, jint dId, jint Id)
{
    return pcgIsDominated(dId, Id);
}

/*
 * Class:     JCovPCG_PCGuidance
 * Method:    pcgIsPostDominated
 * Signature: (II)Z
 */
JNIEXPORT jboolean JNICALL Java_JCovPCG_PCGuidance_pcgIsPostDominated (JNIEnv *env, jclass jc, jint pdId, jint Id)
{
    return pcgIsPostDominated(pdId, Id);
}

#ifdef __cplusplus
}
#endif



