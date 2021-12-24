
#ifndef __MUTATOR_H__
#define __MUTATOR_H__
#include "macro.h"
#include "list.h"
#include "seedpat.h"

typedef struct _mutator_
{
    BYTE *MuName;
    BYTE *StruPattern;
    BYTE *CharPattern;
} Mutator;


VOID InitMutators ();
VOID DeInitMutators ();


VOID RegMutator (BYTE* MuName, BYTE* StruPattern, BYTE* CharPattern);
VOID DumpMutator ();
VOID LoadMutator ();

List* GetMuList ();
Mutator* GetMutator (BYTE* SeedFile);

VOID GenMutator (SeedPat *SP, List *SpList, BYTE* TestName);
VOID BindMutatorToSeeds (Mutator *Mu, BYTE* SeedDir);


SeedPat* MutatorLearning (BYTE* SeedDir);
VOID DeInitSeedPatList ();
List* GetSeedPatList ();


#endif

