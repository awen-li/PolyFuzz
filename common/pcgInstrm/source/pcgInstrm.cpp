

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
    DEBUG ("%s:%u", __FILE__, __LINE__);
    if (pcgHdl != NULL)
    {
        pcgCFGDel ();
    }
    
    pcgHdl = new PCGHandle (EntryId);
    
    return;
}


void pcgCFGEdge (unsigned SNode, unsigned ENode)
{
    DEBUG ("%s:%u", __FILE__, __LINE__);
    CFGGraph *Cfg = pcgHdl->m_BlockCFG;
    Cfg->InsertEdge(SNode, ENode);
    return;
}

void pcgBuild ()
{
#if __DEBUG__
    CFGViz GV ("BlockCFG", pcgHdl->m_BlockCFG);
    GV.WiteGraph ();
#endif
    
    /* compute DOM */
    DEBUG ("Start ComputeDom....\r\n");
    pcgHdl->m_BlockCFG->ComputeDom();
    DEBUG ("Finish ComputeDom....\r\n\r\n");

    /* compute PDOM */
    DEBUG ("Start ComputePostDom....\r\n");
    pcgHdl->m_BlockCFG->ComputePostDom();
    DEBUG ("Finish ComputePostDom....\r\n");
    
    return;
}



bool pcgIsDominated (unsigned SNode, unsigned ENode)
{
    CFGGraph *Cfg = pcgHdl->m_BlockCFG;
    NodeSet* Ns = Cfg->GetDomSet (ENode);
    assert (Ns != NULL);

    for (auto It = Ns->begin (), End = Ns->end (); It != End; It++)
    {
        CFGNode *Cn = *It;
        if (Cn->GetId() == SNode)
        {
            return true;
        }
    }
    
    return false;
}


bool pcgIsPostDominated (unsigned SNode, unsigned ENode)
{
    CFGGraph *Cfg = pcgHdl->m_BlockCFG;
    NodeSet* Ns = Cfg->GetPostDomSet (ENode);
    assert (Ns != NULL);

    for (auto It = Ns->begin (), End = Ns->end (); It != End; It++)
    {
        CFGNode *Cn = *It;
        if (Cn->GetId() == SNode)
        {
            return true;
        }
    }
    
    return false;
}

bool pcgNeedInstrumented (unsigned Id)
{
    DEBUG ("%s:%u", __FILE__, __LINE__);
    CFGGraph *Cfg = pcgHdl->m_BlockCFG;
    CFGNode *Cn = Cfg->GetGNode(Id);
    if (Cn == NULL)
    {
        /* default true */
        return true;
    }

    /* must instrument the entry block*/
    if (Cn == Cfg->GetEntry())
    {
        return true;
    }

    /* Do not instrument full dominators, or full post-dominators with multiple predecessors. */
    if (Cfg->IsFullDominator(Id) ||
        (Cfg->IsFullPostDominator(Id) && Cn->GetIncomingEdgeNum() > 1))
    {
        return false;
    }

    return true;
}



#ifdef __cplusplus
}
#endif

