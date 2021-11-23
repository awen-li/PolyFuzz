
/***********************************************************
 * Author: Wen Li
 * Date  : 11/22/2021
 * Describe: DynTrace.h - dynamic tracing for language components
 * History:
   <1> 11/22/2021 , create
************************************************************/
#ifndef _DYNTRACE_H_
#define _DYNTRACE_H_
#include "Event.h"
#include "Queue.h"


#ifdef __cplusplus
extern "C"{
#endif 


void DynTrace (EVENT_HANDLE Eh, unsigned Length, TraceKey Tk);


#ifdef __cplusplus
}
#endif

#endif 
