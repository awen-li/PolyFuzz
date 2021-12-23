
#ifndef __SEEDPAT_H__
#define __SEEDPAT_H__
#include "macro.h"
#include "seed.h"

typedef struct CharPat {
    DWORD CharNum;
    BYTE  *CharVal;
} CharPat;


typedef struct SeedPat 
{
    BYTE StruPattern[256];
    BYTE CharPattern[256];
    
    Seed *Ss;  
    CharPat *CharList;
} SeedPat;


#endif

