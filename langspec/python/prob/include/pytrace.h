
#ifndef _PY_TRACE_H_
#define _PY_TRACE_H_

#include <Python.h>
#include <object.h>
#include <frameobject.h>
#include <opcode.h>
#include <pystate.h>
#include <vector>
#include <iostream>


namespace pyprob {

using namespace std;

void PyInit(const vector<string>& Modules, string BrValXml);

int Tracer (PyObject *obj, PyFrameObject *frame, int what, PyObject *arg);


#if 1
#define DEBUG_PRINT printf
#else
#define DEBUG_PRINT 
#endif


}
#endif 
