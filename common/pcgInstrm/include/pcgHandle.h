#ifndef _PCGHANDLE_H_
#define _PCGHANDLE_H_
#include "BlockCFG.h"

struct PCGHandle
{
    CFGGraph *m_BlockCFG;

    PCGHandle (DWORD EntryId)
    {
        m_BlockCFG = new CFGGraph (EntryId);
        assert (m_BlockCFG != NULL);
    }

    ~PCGHandle ()
    {
        delete m_BlockCFG;
    }
};

#endif

