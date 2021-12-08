#include "pytrace.h"

namespace pyprob {

using namespace std;

void SetupTracer(string PySummary) 
{
    PyInit(PySummary);
    PyEval_SetTrace((Py_tracefunc)Tracer, (PyObject*)NULL);
    //PyEval_SetProfile ((Py_tracefunc)Tracer, (PyObject*)NULL);
}



}  // namespace atheris
