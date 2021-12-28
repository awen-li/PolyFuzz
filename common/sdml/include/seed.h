
#ifndef __SEED_H__
#define __SEED_H__
#include "macro.h"
#include "list.h"

typedef struct _Seed_ 
{
    BYTE SName[512];

    BYTE* SeedCtx;
    DWORD SeedLen;

    BYTE* SeedSD;
    DWORD SeedSDLen;
} Seed;


typedef struct _N_gram_ 
{
    BYTE Gram[MAX_PAT_LENGTH+4];
    DWORD N_num;
}N_gram;

List* GetSeedList ();

#endif

