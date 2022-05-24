
#include <iostream>
#include "BBstat.h"


string GetCmd (int argc, char *argv[])
{
    int Index = 1;
    string Cmd = "";

    while (Index < argc)
    {
        Cmd += string (argv[Index]) + " ";
        Index++;
    }
    
    return Cmd;
}


int main(int argc, char *argv[])
{
    string Cmd = GetCmd (argc, argv);
    if (Cmd == "")
    {
        cout<<"Please input correct command...\r\n";
        return 0;
    }
    
    BBstat bbStat (Cmd);
    bbStat.Collect();

    return 0;
}




