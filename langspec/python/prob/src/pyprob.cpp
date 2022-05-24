
#include "setup.h"
#include "pybind11/functional.h"
#include "pybind11/pybind11.h"
#include "pybind11/stl.h"

namespace pyprob {


PYBIND11_MODULE(pyprob, PyModule) {

    PyModule.def("Setup",  &SetupTracer);
    PyModule.def("PyExcept",  &PyExcept);

}

} 

