
#ifndef _LOAD_BRVAL_H_
#define _LOAD_BRVAL_H_

#include <iostream>
#include <set>
#include <unordered_map>
#include <assert.h>

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
        cout<<"@@@ "<<m_FuncName<<" -> BrVals: ";
        for (auto It = m_BrVals.begin (); It != m_BrVals.end (); It++)
        {
            cout<<*It<<" ";
        }
        cout<<endl;
    }
};

struct BV_file
{
    string m_FileName;
    BV_function *m_BVFuncCatch;
    unordered_map <string, BV_function> m_Fname2BVf;

    
    BV_file (string FileName)
    {
        m_FileName = FileName;
        m_Fname2BVf.clear ();

        m_BVFuncCatch = NULL;
    }
    
    inline BV_function* Insert (string FuncName)
    {
        auto It = m_Fname2BVf.insert (make_pair(FuncName, BV_function (FuncName))).first;
        assert (It != NULL);
        return &It->second;
    }
};



void LoadBrVals(string BrValXml, unordered_map <string, BV_file> *Fname2BVfile);

}
#endif 
