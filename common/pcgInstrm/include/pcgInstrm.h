#ifndef _PCG_INSTRM_H_
#define _PCG_INSTRM_H_

#ifdef __cplusplus
extern "C"{
#endif

unsigned pcgCFGAlloct (unsigned EntryId);
void pcgCFGDel (unsigned Handle);

void pcgCFGEdge (unsigned Handle, unsigned SNode, unsigned ENode);
void pcgInsertIR (unsigned Handle, unsigned BlockId, const char* SaIR);

void pcgBuild (unsigned Handle);

bool pcgNeedInstrumented (unsigned Handle, unsigned Node);

bool pcgIsDominated (unsigned Handle, unsigned SNode, unsigned ENode);
bool pcgIsPostDominated (unsigned Handle, unsigned SNode, unsigned ENode);


#ifdef __cplusplus
}
#endif

#endif

