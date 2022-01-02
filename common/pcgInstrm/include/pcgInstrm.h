#ifndef _PCG_INSTRM_H_
#define _PCG_INSTRM_H_

#ifdef __cplusplus
extern "C"{
#endif

void pcgCFGAlloct (unsigned NodeNum);
void pcgCFGEdge (unsigned SNode, unsigned ENode);
void pcgBuild ();


unsigned pcgIsDominated (unsigned SNode, unsigned ENode);
unsigned pcgIsPostDominated (unsigned SNode, unsigned ENode);


#ifdef __cplusplus
}
#endif

#endif

