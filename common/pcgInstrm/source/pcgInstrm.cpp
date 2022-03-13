

#include "pcgHandle.h"

static PCGHandle pcgHdl;


#ifdef __cplusplus
extern "C"{
#endif 
#include "MacroDef.h"

void pcgCFGDel (unsigned Handle)
{
    pcgHdl.DelHandle(Handle);
    return;
}


unsigned pcgCFGAlloct (unsigned EntryId)
{
    unsigned Handle = pcgHdl.AlotHandle (EntryId);
    assert (Handle != 0);
    DEBUG ("pcgCFGAlloct: Allot Handle [%u] with EntryID: %u\r\n", Handle, EntryId);

    return Handle;
}


void pcgCFGEdge (unsigned Handle, unsigned SNode, unsigned ENode)
{
    DEBUG ("pcgCFGEdge:%u -> %u\r\n", SNode, ENode);
    CFGGraph *Cfg = pcgHdl.GetCFG (Handle);
    assert (Cfg != NULL);
    
    Cfg->InsertEdge(SNode, ENode);
    return;
}

void pcgInsertIR (unsigned Handle, unsigned BlockId, const char* SaIR)
{
    CFGGraph *Cfg = pcgHdl.GetCFG (Handle);
    
    CFGNode *CfgNode = Cfg->GetGNode (BlockId);
    CfgNode->AddStmtIR(SaIR);
    
    return;
}


void pcgBuild (unsigned Handle)
{
    CFGGraph *Cfg = pcgHdl.GetCFG (Handle);
    
#if __DEBUG__
    CFGViz GV ("BlockCFG", Cfg);

    CFGNode* Entry = Cfg->GetEntry();
    GV.WiteGraph (Entry->GetId());
#endif
    
    /* compute DOM */
    DEBUG ("@@@ Start BuildCFG....\r\n");
    Cfg->BuildCFG();
    
    return;
}



bool pcgIsDominated (unsigned Handle, unsigned SNode, unsigned ENode)
{
    CFGGraph *Cfg = pcgHdl.GetCFG (Handle);
    assert (Cfg != NULL);
    
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


bool pcgIsPostDominated (unsigned Handle, unsigned SNode, unsigned ENode)
{
    CFGGraph *Cfg = pcgHdl.GetCFG (Handle);
    assert (Cfg != NULL);
    
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

bool pcgNeedInstrumented (unsigned Handle, unsigned Id)
{
    CFGGraph *Cfg = pcgHdl.GetCFG (Handle);
    assert (Cfg != NULL);
    
    CFGNode *Cn = Cfg->GetGNode(Id);
    if (Cn == NULL)
    {
        /* default true */
        DEBUG ("Node-%u refered to a CFGNode, dead code or excepton block \r\n", Id);
        return false;
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


unsigned pcgGetPCGStmtID (unsigned Handle, unsigned Id)
{
    CFGGraph *Cfg = pcgHdl.GetCFG (Handle);
    assert (Cfg != NULL);
    
    CFGNode *Cn = Cfg->GetGNode(Id);

    return Cn->GetPCGStmtID ();
}


unsigned pcgGetAllSAIStmtIDs (unsigned Handle, unsigned** SAIStmtIDs)
{
    CFGGraph *Cfg = pcgHdl.GetCFG (Handle);
    assert (Cfg != NULL);

    return Cfg->GetAllSAIStmts(SAIStmtIDs);
}



#ifdef __cplusplus
}
#endif

