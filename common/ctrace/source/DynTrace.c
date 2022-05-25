
#ifdef __cplusplus
extern "C"{
#endif

#include <sys/syscall.h>
#include <sys/shm.h>
#include "Queue.h"
#include "DynTrace.h"
#include "config.h"


/* defined in AFL++ */
static char* afl_area_ptr = NULL;
extern char* __afl_get_area_ptr (void); 
extern void  __afl_set_ext_loc (unsigned ext_loc);
extern int   __afl_get_interal_loc (void);
extern void  __afl_manual_init(void); 
extern void __sanitizer_cov_trace_pc_guard(unsigned *guard);


void DynTrace (EHANDLE Eh, unsigned Length, unsigned BlkId)
{
    if (Eh != NULL)
    {
        QNode *Node = QBUF2QNODE (Eh);

        Node->TrcKey   = BlkId;
        Node->IsReady  = TRUE;
    }

    #if 0
    unsigned char CovVal = afl_area_ptr[TrcKey];
    afl_area_ptr[TrcKey] = CovVal + 1 + (CovVal == 255 ? 1 : 0);
    #else
    __sanitizer_cov_trace_pc_guard (&BlkId);
    #endif

    DEBUG ("[TraceKey:%u][Length=%u]\r\n", BlkId, Length);

    return;   
}

void DynTracePCG (unsigned BlkId)
{
    __sanitizer_cov_trace_pc_guard (&BlkId);

    return;   
}


static inline void DynTraceToQueue (unsigned Key, unsigned ValLength, unsigned long Value)
{
    QNode* QN = InQueue ();
    if (QN == NULL)
    {
        return;
    }
    //while ((QN  = InQueue ()) == NULL);
    
    QN->TrcKey = Key;

    ObjValue *OV = (ObjValue *)QN->Buf;
    OV->Attr   = 0;
    OV->Length = (unsigned short)ValLength;
    OV->Value  = Value;

    switch (OV->Length)
    {
        case 1:  OV->Type = VT_CHAR;  break;
        case 2:  OV->Type = VT_WORD;  break;
        case 4:  OV->Type = VT_DWORD; break;
        case 8:  OV->Type = VT_LONG;  break;
        default: OV->Type = VT_UNKNOWN; break;
    }

    QN->IsReady = 1;
    DEBUG ("[DynTraceToQueue][Key:%u]Type:%u, Length:%u, Value:%lu\r\n", Key, OV->Type, OV->Length, OV->Value);
    return;
}


void DynTraceD8 (unsigned BlkId, unsigned Key, unsigned char Value) 
{
    if (BlkId != 0)
    {
        __sanitizer_cov_trace_pc_guard (&BlkId);
    }
        
    DynTraceToQueue (Key, 1, Value);
    return;
}


void DynTraceD16 (unsigned BlkId, unsigned Key, unsigned short Value) 
{
    if (BlkId != 0)
    {
        __sanitizer_cov_trace_pc_guard (&BlkId);
    }
        
    DynTraceToQueue (Key, 2, Value);
    return;
}


void DynTraceD32 (unsigned BlkId, unsigned Key, unsigned Value) 
{
    if (BlkId != 0)
    {
        __sanitizer_cov_trace_pc_guard (&BlkId);
    }
        
    DynTraceToQueue (Key, 4, Value);
    return;
}


void DynTraceD64 (unsigned BlkId, unsigned Key, unsigned long Value) 
{
    if (BlkId != 0)
    {
        __sanitizer_cov_trace_pc_guard (&BlkId);
    }
        
    DynTraceToQueue (Key, 8, Value);
    return;
}

int DynTraceInit (unsigned BBs)
{
    /* set external language BBs */
    __afl_set_ext_loc (BBs);
    
    /* init fork server */
    __afl_manual_init ();

    afl_area_ptr = __afl_get_area_ptr ();

    int IntLoc =  __afl_get_interal_loc ();

    /* init event queue */ 
    InitQueue(MEMMOD_SHARE);
    
    return IntLoc;
}

void DynTraceExit ()
{
    SetQueueExit ();
}

#ifdef __cplusplus
}
#endif


