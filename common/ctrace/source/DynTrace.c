
#include <sys/syscall.h>
#include <sys/shm.h>
#include "DynTrace.h"
#include "config.h"


#ifdef __cplusplus
extern "C"{
#endif

/* defined in AFL++ */
static char* afl_area_ptr = NULL;
extern char* __afl_get_area_ptr (void); 
extern void  __afl_set_ext_loc (unsigned ext_loc);
extern int   __afl_get_interal_loc (void);
extern void  __afl_manual_init(void); 


void DynTrace (EVENT_HANDLE Eh, unsigned Length, unsigned TrcKey)
{
    QNode *Node = QBUF2QNODE (Eh);

    Node->ThreadId = pthread_self ();
    Node->TrcKey   = TrcKey;
    Node->Flag     = TRUE;

    
    unsigned char CovVal = afl_area_ptr[TrcKey];
    afl_area_ptr[TrcKey] = CovVal + 1 + (CovVal == 255 ? 1 : 0);

    DEBUG ("[DynTrace][T:%u][L:%u]%lx\r\n", Node->ThreadId, Length, TrcKey);

    return;   
}


int DynTraceInit (unsigned BBs)
{
    /* set external language BBs */
    __afl_set_ext_loc (BBs);
    
    /* init fork server */
    __afl_manual_init ();

    afl_area_ptr = __afl_get_area_ptr ();

    return __afl_get_interal_loc ();
}

void DynTraceExit ()
{
    QueueSetExit ();
}

#ifdef __cplusplus
}
#endif


