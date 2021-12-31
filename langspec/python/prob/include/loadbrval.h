
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

struct BV_function
{
    unsigned m_Idx;

    unsigned m_SLine;
    unsigned m_ELine;
    
    string m_FuncName;
    set<string> m_BrVals;
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

    inline void InsertBv (string BrVal)
    {
        m_BrVals.insert (BrVal);
        return;
    }

    inline void InsertBb (string Bb)
    {
        m_BBs.push_back (stoi(Bb));
        return;
    }

    inline void View ()
    {        
        printf("@@@ %s -> #BVs: ", m_FuncName.c_str());
        for (auto It = m_BrVals.begin (); It != m_BrVals.end (); It++)
        {
            printf ("%s ", (*It).c_str());
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
        PY_PRINT("~BV_file\r\n");
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
        PY_PRINT("~BV_set\r\n");
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

    void LoadBrVals(string BrValXml);
    int GetFIdx (string File, string Func, unsigned LineNo);
};



}
#endif 
