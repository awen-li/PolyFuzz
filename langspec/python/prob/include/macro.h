
#ifndef _PY_MACRO_H_
#define _PY_MACRO_H_

#include <iostream>

namespace pyprob {

#if 0
#define PY_PRINT("<Python>"format, ...) printf(format, ##__VA_ARGS__)
#else
#define PY_PRINT(format, ...) 
#endif



}
#endif 