

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
    DEBUG ("pcgCFGAlloct:%u\r\n", EntryId);
    if (pcgHdl != NULL)
    {
        pcgCFGDel ();
    }
    
    pcgHdl = new PCGHandle (EntryId);
    
    return;
}


void pcgCFGEdge (unsigned SNode, unsigned ENode)
{
    DEBUG ("pcgCFGEdge:%u -> %u\r\n", SNode, ENode);
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
    DEBUG ("@@@ Start BuildCFG....\r\n");
    pcgHdl->m_BlockCFG->BuildCFG();
    
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
    CFGGraph *Cfg = pcgHdl->m_BlockCFG;
    CFGNode *Cn = Cfg->GetGNode(Id);
    if (Cn == NULL)
    {
        /* default true */
        DEBUG ("Node-%u refered to a CFGNode failed, Need Instrumented by default\r\n", Id);
        return true;
    }

    /* must instrument the entry block*/
    if (Cn == Cfg->GetEntry())
    {
        DEBUG ("Node-%u is a entry-block, Need Instrumented!\r\n", Id);
        return true;
    }

    /* Do not instrument full dominators, or full post-dominators with multiple predecessors. */
    if (Cfg->IsFullDominator(Id) ||
        (Cfg->IsFullPostDominator(Id) && Cn->GetIncomingEdgeNum() > 1))
    {
        DEBUG ("Node-%u is a full-dominator, Need not Instrumented\r\n", Id);
        return false;
    }

    DEBUG ("Node-%u is Need Instrumented!\r\n", Id);
    return true;
}



#ifdef __cplusplus
}
#endif

