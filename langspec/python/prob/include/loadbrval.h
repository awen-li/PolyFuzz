
#ifndef _LOAD_BRVAL_H_
#define _LOAD_BRVAL_H_

#include <iostream>
#include <set>
#include <vector>
#include <unordered_map>
#include <assert.h>
#include "macro.h"

namespace pyprob {

using namespace std;

struct BVar
{
    unsigned m_LineNo;
    unsigned m_Key;
    string m_Name;

    BVar (unsigned LineNo, string BrVarName, unsigned BrVarKey)
    {
        m_LineNo = LineNo;
        m_Key    = BrVarKey;
        m_Name   = BrVarName;
    }
};


struct BV_file
{
    string m_FileName;
    unordered_map<unsigned, BVar*> m_BrVals;
    vector<int> m_BBs;

    BV_file (string FileName)
    {
        m_FileName = FileName;
    }

    ~BV_file ()
    {
         
    }
    
    inline void InsertBb (string Bb)
    {
        int BbNo = stoi(Bb);
        unsigned Size = (unsigned) m_BBs.size ();
        if (Size != 0 && m_BBs[Size-1] == BbNo)
        {
            return;
        }
            
        m_BBs.push_back (BbNo);
        return;
    }

    inline void InsertBv (unsigned LineNo, string BrVarName, unsigned BrVarKey)
    {
        m_BrVals[LineNo] = new BVar (LineNo, BrVarName, BrVarKey);
        return;
    }
};


typedef unordered_map <string, BV_file*>::iterator fb_iterator;

struct BV_set
{
    unsigned m_Branchs;
    unordered_map <string, BV_file*> m_Fname2BVfile;

    BV_set ()
    {
        m_Branchs = 0;
        m_Fname2BVfile.clear ();
    }

    ~BV_set ()
    {
        //PY_PRINT("~BV_set\r\n");
        for (auto It = m_Fname2BVfile.begin (), End = m_Fname2BVfile.end (); It != End; It++)
        {
            delete It->second;
        }
    }

    inline BV_file* Insert (string FileName)
    {
        BV_file *Bf = new BV_file (FileName);
        assert (Bf != NULL);
        
        m_Fname2BVfile[FileName] = Bf;
        return Bf;
    }

    inline BV_file* Get (string FileName)
    {
        auto It = m_Fname2BVfile.find (FileName);
        if (It == m_Fname2BVfile.end ())
        {
            return NULL;
        }
        return It->second;
    }

    inline fb_iterator begin ()
    {
        return m_Fname2BVfile.begin ();
    }

    inline fb_iterator end ()
    {
        return m_Fname2BVfile.end ();
    }

    void DecodeBrVars (BV_file *BVfunc,       char *BrVars);
    unsigned LoadPySummary(string BrValXml);
};



}
#endif 
