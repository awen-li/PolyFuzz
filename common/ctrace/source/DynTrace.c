
#include <sys/syscall.h>
#include "DynTrace.h"


#ifdef __cplusplus
extern "C"{
#endif

void DynTrace (EVENT_HANDLE Eh, TraceKey Tk)
{
    QNode *Node = QBUF2QNODE (Eh);

    Node->ThreadId = pthread_self ();
    Node->Tk       = Tk;
    Node->Flag     = TRUE;

    DEBUG ("[TRC_trace][T:%u]%lx\r\n", Node->ThreadId, Tk);

    return;   
}

void DynTraceInit ()
{    
    return;
}

void DynTraceExit ()
{
    QueueSetExit ();
}

#ifdef __cplusplus
}
#endif


