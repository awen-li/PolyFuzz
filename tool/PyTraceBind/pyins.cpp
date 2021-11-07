
#include "trace.h"
#include "pybind11/functional.h"
#include "pybind11/pybind11.h"
#include "pybind11/stl.h"

namespace pyins {

void Setup ()
{
    SetupTracer();
    return;
}

PYBIND11_MODULE(pyins, PyModule) {

  PyModule.def("Setup", &Setup);
}

} // end namespace pyins

