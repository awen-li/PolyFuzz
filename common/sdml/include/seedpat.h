
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
  Seed *Ss;  

  CharPat *CharList;
} SeedPat;


#endif

