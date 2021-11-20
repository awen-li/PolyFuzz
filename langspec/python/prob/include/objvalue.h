
#ifndef _OBJ_VALUE_H_
#define _OBJ_VALUE_H_

#include <iostream>

typedef enum
{
    VT_CHAR   = 1,
    VT_SHORT  = 2,
    VT_INT    = 3,
    VT_LONG   = 4,
    VT_FLOAT  = 5,
    VT_DOUBLE = 6,
    VT_STRING = 7,

    VT_LIST   = 17,
    VT_DICT   = 18,
    VT_SET    = 19,
    VT_OBJ    = 20,
}ValueType;


typedef struct ObjValue
{
    unsigned char  Type;
    unsigned char  Attr;
    unsigned short Length;
    unsigned long  Value;
} ObjValue;


#endif 
