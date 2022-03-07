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
#include "pl_message.h"

#define FZ_SAMPLE_NUM        (32)
#define FZ_SEED_NAME_LEN     (512)
#define MAX_THREAD_NUM       (256)
#define LEARN_BLOCK_SIZE     (128)
#define LEARN_BLOCK_NUM      (32)
#define GEN_SEED             ("gen_seeds")


typedef struct _Seed_ 
{
    BYTE SName[FZ_SEED_NAME_LEN];

    BYTE* SeedCtx;
    DWORD SeedLen;

    BYTE* SeedSD;
    DWORD SeedSDLen;

    List SdBlkList;
    DWORD IsLearned;
    DWORD SeedId;
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


typedef struct SeedBlock
{
    Seed *Sd;
    
    DWORD SIndex;
    DWORD Length;

    ULONG Value[FZ_SAMPLE_NUM];
} SeedBlock;


typedef struct BrVariable
{
    DWORD Key;
    WORD Type;
    WORD ValNum;

    WORD ValIndex;
    BYTE Rev[6];
    
    ULONG Value[FZ_SAMPLE_NUM];
    BYTE  ValideTag[FZ_SAMPLE_NUM];
}BrVariable;


typedef struct BsValue
{
    ULONG *ValueList;
    DWORD ValueNum;
    DWORD ValueCap;
}BsValue;


typedef enum
{
    SRV_S_STARTUP = 0,
    SRV_S_SEEDRCV,
    SRV_S_ITB,
    SRV_S_ITE,
    SRV_S_FIN
}SRV_STATE;


typedef struct PLOption
{
    DWORD SdPattBits;
    DWORD SdType;    /* SEED_TEXT: text, SEED_BINARY: binary */
    DWORD LnThrNum;
    DWORD TryLength;
    BYTE  *BvDir;

    DWORD SeedBlock[8];
    DWORD SeedBlockNum;
}PLOption;

typedef struct ThrData
{
    BYTE TrainFile[FZ_SEED_NAME_LEN];
    SeedBlock SdBlk;
    DWORD Status;
    BYTE *LearnThrs;
    BYTE *BvDir;
}ThrData;

typedef struct ThrResrc
{
    DWORD RequiredNum;
    ThrData TD[MAX_THREAD_NUM];
    mutex_lock_t RnLock;
}ThrResrc;

typedef struct SocketInfo
{
    INT SockFd;
    struct sockaddr_in ClientAddr;
    BYTE SrvSendBuf[SRV_BUF_LEN];
    BYTE SrvRecvBuf[SRV_BUF_LEN];
}SocketInfo;

typedef struct DB_HANDLE
{
    DWORD DBSeedHandle;
    DWORD DBSeedBlockHandle;
    DWORD DBBrVariableHandle;
    DWORD DBBrVarKeyHandle;
    DWORD DBCacheBrVarHandle;
}DbHandle;

typedef enum
{
    RUNMOD_PILOT=1,
    RUNMOD_STANDD=2,
    //////////////////////////////
    RUNMOD_NUM=RUNMOD_STANDD,
}RUNMOD;


typedef struct PilotData
{
    DWORD SrvState;
    DWORD FzExit;
    
    PLOption *PLOP;
    DbHandle  *DHL;

    Seed *CurSeed;
    SeedBlock* CurSdBlk;
    
    BYTE* CurSeedName;
    DWORD CurAlign;
    DWORD GenSeedNum;    
    BYTE NewSeedPath[FZ_SEED_NAME_LEN];

    DWORD LearnStat[LEARN_BLOCK_NUM]; /* support size 64 * LEARN_BLOCK_NUM */
}PilotData;


typedef struct StanddData
{
    DWORD SrvState;
    DWORD FzExit;
    
    PLOption *PLOP;
    DbHandle  *DHL;

    mutex_lock_t SDLock;
    DWORD BrVarChange;
    Seed *CurSeed;
}StanddData;

typedef struct PLServer
{
    PLOption PLOP;
    ThrResrc LearnThrs;

    DWORD RunMode;
    PilotData PD;
    StanddData SD;

    SocketInfo SkInfo;
    DbHandle   DHL;
    
}PLServer;


#endif

