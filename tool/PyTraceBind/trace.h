
#ifndef _PY_RACE_H_
#define _PY_RACE_H_

#include <Python.h>
#include <vector>
#include <iostream>


namespace pyins {

using namespace std;

void SetupTracer();
void PyInit(const vector<string>& Modules);


}
#endif 
