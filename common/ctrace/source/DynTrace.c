
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


void DynTrace (EVENT_HANDLE Eh, unsigned Length, unsigned TrcKey)
{
    if (Eh != NULL)
    {
        QNode *Node = QBUF2QNODE (Eh);

        Node->TrcKey   = TrcKey;
        Node->IsReady  = TRUE;
    }

    #if 0
    unsigned char CovVal = afl_area_ptr[TrcKey];
    afl_area_ptr[TrcKey] = CovVal + 1 + (CovVal == 255 ? 1 : 0);
    #else
    __sanitizer_cov_trace_pc_guard (&TrcKey);
    #endif

    DEBUG ("[TraceKey:%u][Length=%u]\r\n", TrcKey, Length);

    return;   
}


static inline void DumpInteralLoc (int IntLoc)
{
    FILE *F = fopen ("INTERAL_LOC", "w");
    assert (F != NULL);
    fprintf (F, "%u", IntLoc);
    fclose (F);
}

int DynTraceInit (unsigned BBs)
{
    /* set external language BBs */
    __afl_set_ext_loc (BBs);
    
    /* init fork server */
    __afl_manual_init ();

    afl_area_ptr = __afl_get_area_ptr ();

    int IntLoc =  __afl_get_interal_loc ();
    DumpInteralLoc (IntLoc);

    /* init event queue */
    char *shmQCap = getenv(SHM_QUEUE_CAP);
    if (shmQCap != NULL)
    {
        InitQueue((unsigned)atoi (shmQCap), getenv (SHM_QUEUE_KEY), MEMMOD_SHARE);
    }
    else
    {
        InitQueue(1024, getenv (SHM_QUEUE_KEY), MEMMOD_SHARE);
    }
    
    return IntLoc;
}

void DynTraceExit ()
{
    SetQueueExit ();
}

#ifdef __cplusplus
}
#endif


