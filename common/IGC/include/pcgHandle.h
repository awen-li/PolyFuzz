#ifndef _PCGHANDLE_H_
#define _PCGHANDLE_H_
#include "BlockCFG.h"

using namespace std;

struct PCGHandle
{
    unsigned m_MaxBlockId;
    unsigned m_HandleNo;
    map <DWORD, CFGGraph*> m_ID2BCFG;
    mutex_lock_t m_hLock;

    PCGHandle ()
    {
        m_MaxBlockId = 0;
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
            unsigned MaxBID = Cfg->GetMaxNodeId();
            if (MaxBID > m_MaxBlockId)
            {
                m_MaxBlockId = MaxBID;
            }
            
            m_ID2BCFG.erase (Handle);
        }

        FILE *F = fopen ("EXTERNAL_LOC", "w");
        if (F != NULL)
        {
            fprintf (F, "%u", m_MaxBlockId);
            fclose (F);
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

