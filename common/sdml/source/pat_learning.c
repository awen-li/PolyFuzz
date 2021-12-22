#include "mutator.h"

static inline VOID RunPilotFuzzing (BYTE* DriverDir)
{
    BYTE Cmd[1024];

    snprintf (Cmd, sizeof (Cmd), "cd %s; ./run-fuzzer.sh -P 1", DriverDir);

    printf ("CMD: %s \r\n", Cmd);
    system (Cmd);
    return;
}

Mutator* MutatorLearning (BYTE* DriverDir)
{
    RunPilotFuzzing (DriverDir);
    
    return NULL;
}

