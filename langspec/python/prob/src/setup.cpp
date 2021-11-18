#include "pytrace.h"

namespace pyprob {

using namespace std;

void SetupTracer(const vector<string>& Modules, string BrValXml) 
{
    PyInit(Modules, BrValXml);
    PyEval_SetTrace((Py_tracefunc)Tracer, (PyObject*)NULL);
    PyEval_SetProfile ((Py_tracefunc)Tracer, (PyObject*)NULL);
}



}  // namespace atheris
