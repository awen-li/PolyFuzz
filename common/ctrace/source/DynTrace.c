
#include <sys/syscall.h>
#include <sys/shm.h>
#include "DynTrace.h"
#include "config.h"


#ifdef __cplusplus
extern "C"{
#endif

static char* AFL_BITMAP = NULL;
static unsigned* AFL_BITMAP_LEN = NULL;


void DynTrace (EVENT_HANDLE Eh, unsigned Length, TraceKey Tk)
{
    QNode *Node = QBUF2QNODE (Eh);

    Node->ThreadId = pthread_self ();
    Node->Tk       = Tk;
    Node->Flag     = TRUE;

    DEBUG ("[DynTrace][T:%u][L:%u]%lx\r\n", Node->ThreadId, Length, Tk);

    return;   
}

static inline void AFL_InitPCmap () 
{
    char *ShmIDStr = getenv(SHM_FUZZ_ENV_VAR);

    if (ShmIDStr) 
    {
        char *BitMap = NULL;

#ifdef USEMMAP
        const char *shm_file_path = ShmIDStr;
        unsigned ShmId = -1;

        /* create the shared memory segment as if it was a file */
        ShmId = shm_open(shm_file_path, O_RDWR, DEFAULT_PERMISSION);
        if (ShmId == -1) 
        {
            fprintf(stderr, "shm_open() failed for fuzz\n");
            exit(1);
        }

        BitMap = (char *) mmap (0, MAX_FILE + sizeof(unsigned), PROT_READ, MAP_SHARED, ShmId, 0);
#else
        unsigned ShmId = atoi(ShmIDStr);
        BitMap = (char *) shmat(ShmId, NULL, 0);
#endif

        if (!BitMap || BitMap == (void *)-1) 
        {
            perror("Could not access fuzzing shared memory");
            exit(1);
        }

        AFL_BITMAP_LEN = (unsigned *)BitMap;
        AFL_BITMAP = BitMap + sizeof(unsigned);
    } 
    else 
    {
        fprintf(stderr, "Error: variable for fuzzing shared memory is not set\n");
        exit(1);
    }

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


