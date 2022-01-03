#ifndef _PCG_INSTRM_H_
#define _PCG_INSTRM_H_

#ifdef __cplusplus
extern "C"{
#endif

void pcgCFGAlloct (unsigned EntryId);
void pcgCFGEdge (unsigned SNode, unsigned ENode);
void pcgBuild ();

bool pcgNeedInstrumented (unsigned Node);

bool pcgIsDominated (unsigned SNode, unsigned ENode);
bool pcgIsPostDominated (unsigned SNode, unsigned ENode);


#ifdef __cplusplus
}
#endif

#endif

