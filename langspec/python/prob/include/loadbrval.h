
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

struct BV_function
{
    unsigned m_Idx;

    unsigned m_SLine;
    unsigned m_ELine;
    
    string m_FuncName;
    unordered_map<unsigned, BVar*> m_BrVals;
    vector<int> m_BBs;

    BV_function (string FuncName, unsigned Idx, unsigned SLine, unsigned ELine)
    {
        m_Idx = Idx;

        m_SLine = SLine;
        m_ELine = ELine;
        
        m_FuncName = FuncName;
        m_BrVals.clear ();
        m_BBs.clear ();
    }

    ~BV_function ()
    {
        for (auto It = m_BrVals.begin (); It != m_BrVals.end (); It++)
        {
            delete It->second;
        }
    }

    inline void InsertBv (unsigned LineNo, string BrVarName, unsigned BrVarKey)
    {
        m_BrVals[LineNo] = new BVar (LineNo, BrVarName, BrVarKey);
        return;
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

    inline void View ()
    {        
        printf("@@@ %s -> #BrVars: ", m_FuncName.c_str());
        for (auto It = m_BrVals.begin (); It != m_BrVals.end (); It++)
        {
            BVar *BV = It->second;
            printf ("%u:%s:%u", It->first, BV->m_Name.c_str(), BV->m_Key);
        }

        printf(", #BBs: ");
        for (auto It = m_BBs.begin (); It != m_BBs.end (); It++)
        {
            printf ("%d ", (*It));
        }
        printf ("\r\n");
    }
};

typedef unordered_map <string, BV_function*>::iterator bv_iterator;
struct BV_file
{
    string m_FileName;
    BV_function *m_BVFuncCatch;
    unordered_map <string, BV_function*> m_Fname2BVfunc;
    unordered_map <unsigned, unsigned> m_Line2FSLine;

    
    BV_file (string FileName)
    {
        m_FileName = FileName;
        m_Fname2BVfunc.clear ();

        m_BVFuncCatch = NULL;
    }

    ~BV_file ()
    {
        //PY_PRINT("~BV_file\r\n");
        for (auto It = m_Fname2BVfunc.begin (), End = m_Fname2BVfunc.end (); It != End; It++)
        {
            delete It->second;
        }
    }
    
    inline BV_function* Insert (string FuncName, unsigned Idx, unsigned SLine, unsigned ELine)
    {
        BV_function *Bvf = new BV_function (FuncName, Idx, SLine, ELine);
        assert (Bvf != NULL);

        string Key = FuncName + to_string (SLine);
        m_Fname2BVfunc [Key] = Bvf;

        unsigned S = SLine;
        while (S <= ELine)
        {
            m_Line2FSLine [S] = SLine;
            S++;
        }
        
        return Bvf;
    }

    inline BV_function* Get (string FuncName, unsigned CurLine)
    {
        auto Lit = m_Line2FSLine.find (CurLine);
        if (Lit == m_Line2FSLine.end())
        {
            return NULL;
        }

        string Key = FuncName + to_string (Lit->second);
        auto It = m_Fname2BVfunc.find (Key);
        if (It == m_Fname2BVfunc.end ())
        {
            return NULL;
        }
        return It->second;
    }

    inline bv_iterator begin ()
    {
        return m_Fname2BVfunc.begin ();
    }

    inline bv_iterator end ()
    {
        return m_Fname2BVfunc.end ();
    }
};


typedef unordered_map <string, BV_file*>::iterator fb_iterator;

struct BV_set
{
    BV_file *m_BVFileCatch;
    unsigned m_Branchs;
    unordered_map <string, BV_file*> m_Fname2BVfile;

    BV_set ()
    {
        m_BVFileCatch = NULL;
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

    void DecodeBrVars (BV_function *BVfunc,       char *BrVars);
    unsigned LoadPySummary(string BrValXml);
    int GetFIdx (string File, string Func, unsigned LineNo);
};



}
#endif 
