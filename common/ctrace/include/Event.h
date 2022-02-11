/***********************************************************
 * Author: Wen Li
 * Date  : 11/22/2021
 * Describe: Event.h - dynamic event definition
 * History:
   <1> 11/22/2021 , create
************************************************************/

#ifndef _DYN_EVENT_H_
#define _DYN_EVENT_H_
#include "MacroDef.h"

#ifdef __cplusplus
extern "C"{
#endif 


typedef enum
{
    ET_VALNAME  = 1,
    ET_VALADDR  = 2,
    ET_VALUE    = 3,

}EventType;


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


typedef BYTE* EHANDLE;

EHANDLE AllocEvent ();
unsigned EncodeEvent (EHANDLE eh, unsigned Esize, unsigned Etype, unsigned Length, BYTE* Value);


#ifdef __cplusplus
}
#endif

#endif 
