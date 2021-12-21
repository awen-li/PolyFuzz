
#ifndef __MUTATOR_H__
#define __MUTATOR_H__
#include "macro.h"

typedef VOID (*__mutator_entry__) (BYTE* SeedBuf, DWORD SeedLen);

typedef struct _mutator
{
    BYTE *Pattern;
    BYTE *MuName;

    __mutator_entry__ MuEntry;
    
} Mutator;


VOID InitMutators ();
VOID RegMutator (BYTE* Pattern, BYTE* MuName);

Mutator* GetMutator (BYTE* SeedFile);


#endif

