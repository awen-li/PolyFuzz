/***********************************************************
 * Author: Wen Li
 * Date  : 11/16/2021
 * Describe: seedpat.h - pattern of seeds
 * History:
   <1> 11/16/2021, create
************************************************************/
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

    List PossPat;
    
    Seed *Ss;  
    CharPat *CharList;
} SeedPat;


#endif

