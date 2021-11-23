
#include <sys/syscall.h>
#include "DynTrace.h"


#ifdef __cplusplus
extern "C"{
#endif

void DynTrace (EVENT_HANDLE Eh, unsigned Length, TraceKey Tk)
{
    QNode *Node = QBUF2QNODE (Eh);

    Node->ThreadId = pthread_self ();
    Node->Tk       = Tk;
    Node->Flag     = TRUE;

    DEBUG ("[DynTrace][T:%u][L:%u]%lx\r\n", Node->ThreadId, Length, Tk);

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


