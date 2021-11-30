
#ifndef _PY_EXCEPTION_H_
#define _PY_EXCEPTION_H_

#include <iostream>
#include <set>
#include <unordered_map>
#include <assert.h>
#include "macro.h"

namespace pyprob {

using namespace std;

#define EXCEP_RECORD ("exception_records.txt")

struct Exception
{
    string m_Type;
    string m_FileName;
    unsigned m_LineNo;
    
    Exception (string Type, string FileName, unsigned LineNo)
    {
        m_Type     = Type;
        m_FileName = FileName;
        m_LineNo   = LineNo;
    }
    
    inline void Dump ()
    {
        FILE *F = fopen (EXCEP_RECORD, "a+");
        assert (F != NULL);

        fprintf (F, "%s:%s:%u\r\n", m_Type.c_str(), m_FileName.c_str(), m_LineNo);
        fclose (F);
    }
};


}
#endif 
