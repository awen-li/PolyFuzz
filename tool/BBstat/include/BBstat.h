
#ifndef _BBSTAT_H_
#define _BBSTAT_H_
#include <set>
#include <map>
#include "MacroDef.h"

using namespace std;

class BBstat 
{    
private:
    string m_BBPath;
    string m_Cmd;
    
    set <DWORD> m_BBset;

private:
    inline VOID ParseBBstat ()
    {
        FILE *bf = fopen (m_BBPath.c_str(), "r");
        if (bf == NULL)
        {
            cout<<"Open "<<m_BBPath<<" fail.....\r\n";
            return;
        }

        DWORD Num = 0;
        while (!feof (bf))
        {
            DWORD BBno = 0;
            fscanf (bf, "%u", &BBno);
            if (BBno == 0)
            {
                continue;
            }
            m_BBset.insert (BBno);
            Num++;
        }

        cout<<"["<<Num<<"]Collect basic block number: "<<m_BBset.size ()<<"\r\n";
        return;
    }

public:

    BBstat(string Cmd, string BBPath="/tmp/BlockNo.log")
    {
        m_Cmd    = Cmd;
        m_BBPath = BBPath;      
    }

    
    inline VOID Collect ()
    {
        remove (m_BBPath.c_str());

        // run the command
        cout<<"Command: "<<m_Cmd<<", and BlockStat path:"<<m_BBPath<<endl;

        m_Cmd = "export DUMP_BLOCK=1 && " + m_Cmd;
        system (m_Cmd.c_str());

        ParseBBstat ();
    }
    
};


#endif 
