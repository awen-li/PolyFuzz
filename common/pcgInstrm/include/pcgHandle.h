#ifndef _PCGHANDLE_H_
#define _PCGHANDLE_H_
#include "BlockCFG.h"
#include "DomTree.h"
#include "PDomTree.h"

struct PCGHandle
{
    CFGGraph *m_BlockCFG;
    DomTree  *m_DomTree;
    PDomTree *m_PDomTree;


    PCGHandle (DWORD EntryId)
    {
        m_BlockCFG = new CFGGraph (EntryId);
        assert (m_BlockCFG != NULL);
        
        m_DomTree  = new DomTree (EntryId);
        assert (m_DomTree != NULL);
        
        m_PDomTree = new PDomTree (EntryId);
        assert (m_PDomTree != NULL);
    }

    ~PCGHandle ()
    {
        delete m_BlockCFG;
        delete m_DomTree;
        delete m_PDomTree;
    }
};

#endif

