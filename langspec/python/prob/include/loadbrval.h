
#ifndef _LOAD_BRVAL_H_
#define _LOAD_BRVAL_H_

#include <iostream>
#include <set>
#include <unordered_map>
#include <assert.h>
#include "macro.h"

namespace pyprob {

using namespace std;

struct BV_function
{
    string m_FuncName;
    set <string> m_BrVals;

    BV_function (string FuncName)
    {
        m_FuncName = FuncName;
        m_BrVals.clear ();
    }

    inline void Insert (string BrVal)
    {
        m_BrVals.insert (BrVal);
        return;
    }

    inline void View ()
    {
        PY_PRINT("%s -> branch variables: ", m_FuncName.c_str());
        for (auto It = m_BrVals.begin (); It != m_BrVals.end (); It++)
        {
            PY_PRINT ("%s ", (*It).c_str());
        }
        PY_PRINT ("\r\n");
    }
};

struct BV_file
{
    string m_FileName;
    BV_function *m_BVFuncCatch;
    unordered_map <string, BV_function> m_Fname2BVfunc;

    
    BV_file (string FileName)
    {
        m_FileName = FileName;
        m_Fname2BVfunc.clear ();

        m_BVFuncCatch = NULL;
    }
    
    inline BV_function* Insert (string FuncName)
    {
        auto It = m_Fname2BVfunc.insert (make_pair(FuncName, BV_function (FuncName))).first;
        assert (It != NULL);
        return &It->second;
    }

    inline BV_function* Get (string FuncName)
    {
        auto It = m_Fname2BVfunc.find (FuncName);
        if (It == m_Fname2BVfunc.end ())
        {
            return NULL;
        }
        return &It->second;
    }
};


struct BV_set
{
    BV_file *m_BVFileCatch;
    unsigned m_Branchs;
    unordered_map <string, BV_file> m_Fname2BVfile;

    BV_set ()
    {
        m_BVFileCatch = NULL;
        m_Branchs = 0;
        m_Fname2BVfile.clear ();
    }

    inline BV_file* Insert (string FileName)
    {
        auto It = m_Fname2BVfile.insert (make_pair(FileName, BV_file (FileName))).first;
        assert (It != NULL);
        return &It->second;
    }

    inline BV_file* Get (string FileName)
    {
        auto It = m_Fname2BVfile.find (FileName);
        if (It == m_Fname2BVfile.end ())
        {
            return NULL;
        }
        return &It->second;
    }

    void LoadBrVals(string BrValXml);
    set <string> *GetBvSet (string File, string Func);
};



}
#endif 
