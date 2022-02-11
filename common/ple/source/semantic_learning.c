#include "seed.h"
#include <dirent.h>
#include <sys/stat.h>
#include <pthread.h>


/////////////////////////////////////////////////////////////////////////////////////////////////////////



/////////////////////////////////////////////////////////////////////////////////////////////////////////
static inline VOID RunPilotFuzzing (BYTE* DriverDir)
{
    BYTE Cmd[1024];
    DWORD StartBB = 0;

    FILE *pf = fopen ("INTERAL_LOC", "r");
    if (pf != NULL)
    {
        fscanf (pf, "%u", &StartBB);
        fclose (pf);
    }

    if (StartBB != 0)
    {
        StartBB++;
        snprintf (Cmd, sizeof (Cmd), "cd %s; export AFL_START_BB=%u && ./run-fuzzer.sh -P 1", DriverDir, StartBB);
    }
    else
    {
        snprintf (Cmd, sizeof (Cmd), "cd %s; ./run-fuzzer.sh -P 1", DriverDir);
    }

    printf ("CMD: %s \r\n", Cmd);
    system (Cmd);
    return;
}


void* PilotFuzzingProc (void *Para)
{
    BYTE* DriverDir = (BYTE *)Para;
    
    while (1);
    
    return NULL;
}


void SemanticLearning (BYTE* SeedDir, BYTE* DriverDir)
{
    pthread_t Tid = 0;
    int Ret = pthread_create(&Tid, NULL, PilotFuzzingProc, DriverDir);
    if (Ret != 0)
    {
        fprintf (stderr, "pthread_create fail, Ret = %d\r\n", Ret);
        return;
    }
    
    /* main thread for pattern learning */
    while (1)
    {
    }

    
    return;
}



