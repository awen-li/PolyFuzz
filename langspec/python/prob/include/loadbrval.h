
#ifndef _LOAD_BRVAL_H_
#define _LOAD_BRVAL_H_

#include <iostream>
#include <set>
#include <unordered_map>


namespace pyprob {

using namespace std;

struct FBrVal
{
    string FuncName;
    set <string> BrVals;

    FBrVal (string &FuncName)
    {
        this->FuncName = FuncName;
    }

    inline void Insert (string BrVal)
    {
        BrVals.insert (BrVal);
        return;
    }
};

extern "C"{
void LoadBrVals(string BrValXml, unordered_map <string, FBrVal> *BrValMap);
}


}
#endif 
