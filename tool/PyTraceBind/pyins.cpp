
#include "trace.h"
#include "pybind11/functional.h"
#include "pybind11/pybind11.h"
#include "pybind11/stl.h"

namespace pyins {


PYBIND11_MODULE(pyins, PyModule) {

  PyModule.def("Setup",  &SetupTracer);
  PyModule.def("PyInit", &PyInit);
}

} // end namespace pyins

