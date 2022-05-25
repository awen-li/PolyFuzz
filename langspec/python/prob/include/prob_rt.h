
#ifndef _PROB_RT_H_
#define _PROB_RT_H_

#include "loadbrval.h"

namespace pyprob {

using namespace std;

struct PRT_function
{
    unsigned m_Idx;

    int m_SBB;
    int m_EBB;
    int m_CovSize;
    
    vector<int> *m_BBs;
    unordered_map<unsigned, BVar*> *m_BrVars;
    
    int *m_ScancovGen;

    int m_PreBB;
    int m_CurBB;

    PRT_function (unsigned Idx, int &BBno, vector<int> *BBs, unordered_map<unsigned, BVar*> *BrVals)
    {
        assert (BBs != NULL);
        
        m_Idx = Idx;
        m_BBs = BBs;
        m_BrVars = BrVals;
        
        m_SBB = BBs->front ();
        m_EBB = BBs->back ();
        m_CovSize = m_EBB-m_SBB+2;      
        assert (m_CovSize >= 1);
        
        m_ScancovGen = new int[m_CovSize];
        assert (m_ScancovGen != NULL);
        PY_PRINT("[%d]m_ScancovGen = %p[%d] \r\n", m_Idx, m_ScancovGen, m_CovSize);

        InitScanCov (BBno);

        m_PreBB = 0;
        m_CurBB = 0;
    }

    ~PRT_function () 
    {
        //PY_PRINT("~PRT_function -> [%d]m_ScancovGen = %p[%d] \r\n", m_Idx, m_ScancovGen, m_CovSize);
        if (m_ScancovGen)
        {
            delete m_ScancovGen;
            m_ScancovGen = NULL;
        }
    }

    BVar* RetrivBrVarKey (unsigned LineNo)
    {
        auto It = m_BrVars->find (LineNo);
        if (It == m_BrVars->end ())
        {
            return NULL;
        }
        else
        {
            return It->second;
        }
    }

    void inline UpdateCurBB (int LineNo)
    {
        if (LineNo < m_SBB)
        {
            return;
        }
        
        m_PreBB = m_CurBB;
        if (LineNo < m_EBB)
        {
            m_CurBB = m_ScancovGen [LineNo - m_SBB];
        }
        else
        {
            m_CurBB = m_ScancovGen [m_EBB - m_SBB];
        }

        return;
    }

    void inline InitScanCov (int &BBno)
    {
        int BBnum = (int)m_BBs->size ();
        assert (BBnum > 0);

        if (BBnum == 1)
        {
            m_ScancovGen [0] = BBno;
            PY_PRINT("InitScanCov: line[%d-++] -> block[%d] \r\n", m_SBB, BBno);
            BBno++;            
        }
        else
        {
            int LineNo = 0;
            for (int CurBB = 1; CurBB < BBnum; CurBB++)
            {   
                int EndBB   = m_BBs->at(CurBB);
                int StartBB = m_BBs->at(CurBB-1);
                if (CurBB > 1) StartBB += 1;
                
                for (LineNo = StartBB; LineNo <= EndBB; LineNo++)
                {
                    m_ScancovGen [LineNo-m_SBB] = BBno;
                }
                PY_PRINT("[%d]InitScanCov: line[%d-%d] -> block[%d] \r\n", BBnum, StartBB, EndBB, BBno);

                BBno++;
            }

            assert (LineNo == m_EBB+1);
            BBno++;
        }
        
        return;
    }
};


struct PRT
{
    set<string> RegModule;
    BV_set BvSet;
    
    unordered_map <unsigned, PRT_function*> m_Idx2Rtf;
    PRT_function *m_CatchRtf;
    unsigned m_InitOkay;

    PRT () 
    {
        m_CatchRtf = NULL;
        m_InitOkay = 0;
        
        RegModule.clear ();
        m_Idx2Rtf.clear ();
        
    }

    ~PRT () 
    {
        for (auto It = m_Idx2Rtf.begin (), End = m_Idx2Rtf.end (); It != End; It++)
        {
            delete It->second;
        }
    }

    inline void InitRtfs (int &BBno)
    {
        if (BBno == 0)
        {
            BBno = 1;
        }
        
        for (auto BvIt = BvSet.begin (), BvEnd = BvSet.end (); BvIt != BvEnd; BvIt++)
        {
            BV_file* Bvf = BvIt->second;
            for (auto fIt = Bvf->begin (), fEnd = Bvf->end (); fIt != fEnd; fIt++)
            {   
                BV_function* BvFunc = fIt->second;

                PY_PRINT("@@@ Start init Rtf: [%d][%s] \r\n", BvFunc->m_Idx, BvFunc->m_FuncName.c_str());
                PRT_function *Rtf = new PRT_function (BvFunc->m_Idx, BBno, &BvFunc->m_BBs, &BvFunc->m_BrVals);
                assert (Rtf != NULL);

                m_Idx2Rtf [BvFunc->m_Idx] = Rtf;     
            }
        }

        m_InitOkay = 1;
        return;        
    }

    inline bool IsRegModule (string Module)
    {
        auto It = RegModule.find (Module);
        if (It == RegModule.end ())
        {
            return false;
        }
        
        return true;
    }

    inline PRT_function* GetRtf (unsigned Idx, int LineNo)
    {
        if (m_CatchRtf != NULL && m_CatchRtf->m_Idx == Idx)
        {
            m_CatchRtf->UpdateCurBB (LineNo);
            return m_CatchRtf;
        }
        
        auto It = m_Idx2Rtf.find (Idx);
        if (It != m_Idx2Rtf.end ())
        {
            m_CatchRtf = It->second;

            m_CatchRtf->m_CurBB = 0;
            m_CatchRtf->UpdateCurBB (LineNo);
            return m_CatchRtf;
        }
        else
        {
            printf ("Unknown Idx: %u \r\n", Idx);
            assert (0);
            return m_CatchRtf;
        }
    }
};


}
#endif 
