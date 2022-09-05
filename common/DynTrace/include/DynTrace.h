
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


#ifdef __cplusplus
extern "C"{
#endif 


int  DynTraceInit (unsigned BBs);
void DynTraceExit ();

void DynTrace (EHANDLE Eh, unsigned Length, unsigned BlkId);

void DynTracePCG (unsigned BlkId);

void DynTraceD8 (unsigned BlkId, unsigned Key, unsigned char Value);
void DynTraceD16 (unsigned BlkId, unsigned Key, unsigned short Value);
void DynTraceD32 (unsigned BlkId, unsigned Key, unsigned Value);
void DynTraceD64 (unsigned BlkId, unsigned Key, unsigned long Value);



#ifdef __cplusplus
}
#endif

#endif 
