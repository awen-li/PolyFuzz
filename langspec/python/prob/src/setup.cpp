#include "pytrace.h"

namespace pyprob {

using namespace std;
void SetDriver (string FileName);


void SetupTracer(string PySummary, string DriverFile) 
{
    PyInit(PySummary);
    SetDriver (DriverFile);
    PyEval_SetTrace((Py_tracefunc)Tracer, (PyObject*)NULL);
    //PyEval_SetProfile ((Py_tracefunc)Tracer, (PyObject*)NULL);
}



}  // namespace atheris
