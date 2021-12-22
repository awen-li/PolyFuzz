
#ifndef __MUTATOR_H__
#define __MUTATOR_H__
#include "macro.h"

typedef VOID (*_mutator_entry_) (BYTE* SeedBuf, DWORD SeedLen);

typedef struct _mutator_
{
    BYTE *Pattern;
    BYTE *MuName;

    _mutator_entry_ MuEntry;
    
} Mutator;


VOID InitMutators ();
VOID DeInitMutators ();


VOID RegMutator (BYTE* Pattern, BYTE* MuName);
VOID DumpMutator ();
VOID LoadMutator ();


Mutator* GetMutator (BYTE* SeedFile);
VOID BindMutatorToSeeds (Mutator *Mu, BYTE* SeedDir);


Mutator* MutatorLearning (BYTE* SeedDir);

#endif

