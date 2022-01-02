#ifndef _PCG_INSTRM_H_
#define _PCG_INSTRM_H_

#ifdef __cplusplus
extern "C"{
#endif

unsigned pcgCFGAlloct (unsigned NodeNum);
unsigned pcgCFGEdge (unsigned SNode, unsigned ENode);

unsigned pcgIsDominated (unsigned SNode, unsigned ENode);
unsigned pcgIsPostDominated (unsigned SNode, unsigned ENode);


#ifdef __cplusplus
}
#endif

#endif

