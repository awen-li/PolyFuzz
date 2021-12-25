
#ifndef _PY_MACRO_H_
#define _PY_MACRO_H_

#include <iostream>

namespace pyprob {

#ifdef __DEBUG__
#define PY_PRINT(format, ...) printf("<Python>" format, ##__VA_ARGS__)
#else
#define PY_PRINT(format, ...) 
#endif



}
#endif 
