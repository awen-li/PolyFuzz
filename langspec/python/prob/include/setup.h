
#ifndef _PY_SETUP_H_
#define _PY_SETUP_H_

#include <vector>
#include <iostream>
#include <Python.h>
#include <pyerrors.h>


namespace pyprob {

using namespace std;

void SetupTracer(string PySummary);

void PyExcept (string Type, string FileName, long LineNo);

}
#endif 
