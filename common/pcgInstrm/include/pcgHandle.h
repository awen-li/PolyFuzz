#ifndef _PCGHANDLE_H_
#define _PCGHANDLE_H_
#include "BlockCFG.h"

using namespace std;

struct PCGHandle
{
    unsigned m_HandleNo;
    map <DWORD, CFGGraph*> m_ID2BCFG;
    mutex_lock_t m_hLock;

    PCGHandle ()
    {
        m_HandleNo = 1;
        mutex_lock_init(&m_hLock);
    }

    ~PCGHandle ()
    {
    }

    inline CFGGraph* GetCFG (DWORD Handle)
    {
        CFGGraph* Cfg = NULL;
        
        mutex_lock(&m_hLock);      
        auto It = m_ID2BCFG.find (Handle);
        if (It != m_ID2BCFG.end ())
        {
            Cfg = It->second;
        }
        mutex_unlock(&m_hLock);

        return Cfg;
    }

    inline DWORD AlotHandle (DWORD EntryId)
    {
        DWORD ID;
        CFGGraph *BlockCFG = new CFGGraph (EntryId);
        assert (BlockCFG != NULL);

        mutex_lock(&m_hLock);
        ID = m_HandleNo++;
        m_ID2BCFG [ID] = BlockCFG;
        mutex_unlock(&m_hLock);

        return ID;
    }

    inline VOID DelHandle (DWORD Handle)
    {
        CFGGraph* Cfg = NULL;
        
        mutex_lock(&m_hLock);
        auto It = m_ID2BCFG.find (Handle);
        if (It != m_ID2BCFG.end ())
        {
            Cfg = It->second;
            m_ID2BCFG.erase (Handle);
        }
        mutex_unlock(&m_hLock);

        if (Cfg != NULL)
        {
            delete Cfg;
        }
        return;
    }
};

#endif

