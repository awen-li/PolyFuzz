
#ifndef __SEEDPAT_H__
#define __SEEDPAT_H__
#include "macro.h"

typedef struct CharPat {
    DWORD CharNum;
    BYTE  *CharVal;
} CharPat;


typedef struct SeedPat 
{
  struct queue_entry *seed;             /* seed */

  DWORD SeedLen;
  u8* seed_ctx;
  char_pat *char_pat_list;

  struct patreg_seed* next;
} SeedPat;


#endif

