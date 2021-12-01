#include <Python.h>
#include <pyerrors.h>
#include <pystate.h>
#include "except.h"


namespace pyprob {

using namespace std;


void PyExcept (string Type, string FileName, long LineNo)
{
    PY_PRINT("Capture exception : %s:%s:%lu \r\n", Type.c_str(), FileName.c_str(), LineNo);
    Exception Exceps (Type, FileName, (unsigned)LineNo);

    Exceps.Dump ();

    /* exit code to inform fork server */
    exit (100);
}



} 

