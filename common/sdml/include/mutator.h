
#ifndef __MUTATOR_H__
#define __MUTATOR_H__
#include "macro.h"
#include "list.h"
#include "seedpat.h"
#include <regex.h> 

typedef struct _mutator_
{
    BYTE *MuName;
    BYTE *StruPattern;
    BYTE CharPattern[256];

    List PossPat;
    regex_t StRegex;
} Mutator;


VOID InitMutators ();
VOID DeInitMutators ();


Mutator* RegMutator (BYTE* MuName, BYTE* StruPattern, BYTE* CharPattern, List *PossPat);
VOID DumpMutator ();
VOID LoadMutator ();

List* GetMuList ();
Mutator* GetMutator (BYTE* SeedDir, BYTE* TestName);


VOID BindMutatorToSeeds (Mutator *Mu, BYTE* SeedDir);


SeedPat* MutatorLearning (BYTE* SeedDir);
VOID DeInitSeedPatList ();
List* GetSeedPatList ();


#endif

