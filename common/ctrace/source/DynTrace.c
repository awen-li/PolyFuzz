
#include <sys/syscall.h>
#include <sys/shm.h>
#include "DynTrace.h"
#include "config.h"


#ifdef __cplusplus
extern "C"{
#endif

extern char* __afl_area_ptr; /* defined in AFL++ */
extern void __afl_manual_init(void); /* defined in AFL++ */


void DynTrace (EVENT_HANDLE Eh, unsigned Length, TraceKey Tk)
{
    QNode *Node = QBUF2QNODE (Eh);

    Node->ThreadId = pthread_self ();
    Node->Tk       = Tk;
    Node->Flag     = TRUE;

    DEBUG ("[DynTrace][T:%u][L:%u]%lx\r\n", Node->ThreadId, Length, Tk);

    return;   
}


char* DynTraceInit ()
{
    /* init fork server */
    __afl_manual_init ();
    return __afl_area_ptr;
}

void DynTraceExit ()
{
    QueueSetExit ();
}

#ifdef __cplusplus
}
#endif


