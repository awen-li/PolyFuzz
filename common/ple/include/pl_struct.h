/***********************************************************
 * Author: Wen Li
 * Date  : 11/18/2021
 * Describe: pl_struct.h - pattern learning interl struct definition
 * History:
   <1> 11/18/2021, create
************************************************************/
#ifndef __PL_STRUCT_H__
#define __PL_STRUCT_H__
#include "macro.h"
#include "list.h"
#include <regex.h> 
#include <sys/socket.h>   
#include <netinet/in.h>   
#include <unistd.h>

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


typedef struct PLServer
{
    INT SockFd;
    struct sockaddr_in ClientAddr;
    BYTE SrvBuf[SRV_BUF_LEN];

    DWORD DBSeedHandle;
    DWORD DBSeedBlockHandle;
    DWORD DBBrVariableHandle;
}PLServer;


typedef struct _SeedBLock_ 
{
    DWORD SIndex;
    DWORD Length;

    List  ValBlock;
} SeedBLock;


typedef struct BrVariable
{
    DWORD Key;
    DWORD Type;
    ULONG Value;
}BrVariable;


typedef enum
{
    SRV_S_INIT = 0,
    SRV_S_STARTUP,
    SRV_S_SEEDRCV,
    SRV_S_ITB,
    SRV_S_ITE,
    SRV_S_FIN
}SRV_STATE;

#endif

