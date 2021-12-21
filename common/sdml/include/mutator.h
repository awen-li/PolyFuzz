
#ifndef __MUTATOR_H__
#define __MUTATOR_H__
#include "macro.h"

typedef VOID (*__mutator_entry__) (BYTE* SeedBuf, DWORD SeedLen);

typedef struct _mutator
{
    BYTE *Pattern;

    __mutator_entry__ MutatorEntry;
    
} Mutator;


VOID reg_mutator (BYTE* Pattern, __mutator_entry__ Mue);

Mutator* get_mutator (BYTE* SeedFile);


#endif

