
#ifndef _PY_TRACE_H_
#define _PY_TRACE_H_

#include <Python.h>
#include <object.h>
#include <frameobject.h>
#include <opcode.h>
#include <pystate.h>
#include <vector>
#include <iostream>
#include "macro.h"


namespace pyprob {

using namespace std;

void PyInit(string PySummary);

int Tracer (PyObject *obj, PyFrameObject *frame, int what, PyObject *arg);


}
#endif 
