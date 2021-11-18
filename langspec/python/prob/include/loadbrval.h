
#ifndef _LOAD_BRVAL_H_
#define _LOAD_BRVAL_H_

#include <iostream>
#include <set>
#include <unordered_map>


namespace pyprob {

using namespace std;

struct FBrVal
{
    string m_FuncName;
    set <string> m_BrVals;

    FBrVal (string FuncName)
    {
        m_FuncName = FuncName;
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

extern "C"{
void LoadBrVals(string BrValXml, unordered_map <string, FBrVal> *BrValMap);
}


}
#endif 
