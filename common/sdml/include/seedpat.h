
#ifndef __SEEDPAT_H__
#define __SEEDPAT_H__
#include "macro.h"
#include "seed.h"
#include <regex.h> 

typedef struct CharPat {
    DWORD CharNum;
    BYTE  *CharVal;
} CharPat;


typedef struct SeedPat 
{
    BYTE StruPattern[256];
    BYTE CharPattern[256];

    regex_t StRegex;
    DWORD MatchNum;
    List UnMatchList;
    
    Seed *Ss;  
    CharPat *CharList;
} SeedPat;


#endif

