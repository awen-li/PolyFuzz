#include "trace.h"
#include <frameobject.h>
#include <opcode.h>
#include <pystate.h>
#include <cstddef>
#include <deque>
#include <iostream>
#include <unordered_map>

namespace pyins {


int Tracer (PyObject *obj, PyFrameObject *frame, int what, PyObject *arg)
{
    switch(what)
    {
        case PyTrace_LINE:
        {
            printf("PyTrace_LINE:%d\n", what);
            break;
        }
        case PyTrace_CALL:
        {
            printf("PyTrace_CALL:%d\n", what);
            break;
        }
        case PyTrace_EXCEPTION:
        {
            printf("PyTrace_EXCEPTION:%d\n", what);
            break;
        }
        case PyTrace_RETURN:
        {
            printf("PyTrace_RETURN:%d\n", what);
            break;
        }
        case PyTrace_OPCODE:
        {
            printf("PyTrace_OPCODE:%d\n", what);
            break;
        }
        case PyTrace_C_CALL:
        {
            printf("PyTrace_C_CALL:%d\n", what);
            break;
        }
        case PyTrace_C_EXCEPTION:
        {
            printf("PyTrace_C_EXCEPTION:%d\n", what);
            break;
        }
        case PyTrace_C_RETURN:
        {
            printf("PyTrace_C_RETURN:%d\n", what);
            break;
        }
        default:
        {
            printf("default: %d\n", what);
            break;
        }
    }
    
    return 0;
}



void SetupTracer() 
{
    PyEval_SetTrace((Py_tracefunc)Tracer, (PyObject*)NULL);
    PyEval_SetProfile ((Py_tracefunc)Tracer, (PyObject*)NULL);
}


void PyInit() 
{
    return;
}

}  // namespace atheris
