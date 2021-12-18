#include <Python.h>
#include <pyerrors.h>
#include <pystate.h>
#include "except.h"


namespace pyprob {

using namespace std;

static string DriverFile = "";

void SetDriver (string FileName)
{
    DriverFile = FileName;
    return;
}

void PyExcept (string Type, string FileName, long LineNo)
{
    PY_PRINT("Capture exception : %s:%s:%lu \r\n", Type.c_str(), FileName.c_str(), LineNo);
    FileName = FileName.substr(FileName.find_last_of("/") + 1);
    if (FileName == DriverFile)
    {
        return;
    }
    
    Exception Exceps (Type, FileName, (unsigned)LineNo);

    Exceps.Dump ();

    /* exit code to inform fork server */
    exit (100);
}



} 

