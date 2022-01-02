

#include "pcgHandle.h"

static PCGHandle *pcgHdl = NULL;


#ifdef __cplusplus
extern "C"{
#endif 
#include "MacroDef.h"

void pcgCFGDel ()
{
    delete pcgHdl;
    pcgHdl = NULL;
}


void pcgCFGAlloct (unsigned EntryId)
{
    if (pcgHdl != NULL)
    {
        pcgCFGDel ();
    }
    
    pcgHdl = new PCGHandle (EntryId);
    
    return;
}


void pcgCFGEdge (unsigned SNode, unsigned ENode)
{
    CFGGraph *Cfg = pcgHdl->m_BlockCFG;
    Cfg->InsertEdge(SNode, ENode);
    return;
}

void pcgBuild ()
{
    CFGViz GV ("BlockCFG", pcgHdl->m_BlockCFG);
    GV.WiteGraph ();
    
    /* construct DOMT */

    /* construct PDOMT */
    return;
}



unsigned pcgIsDominated (unsigned SNode, unsigned ENode)
{
    return 0;
}


unsigned pcgIsPostDominated (unsigned SNode, unsigned ENode)
{
    return 0;
}


#ifdef __cplusplus
}
#endif

