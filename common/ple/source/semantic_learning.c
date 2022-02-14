#include "ctrace/Event.h"
#include <pthread.h>
#include "db.h"
#include "Queue.h"
#include "pl_struct.h"
#include "pl_message.h"


static PLServer g_plSrv;

BYTE* ReadFile (BYTE* SeedFile, DWORD *SeedLen, DWORD SeedAttr);
/////////////////////////////////////////////////////////////////////////////////////////////////////////
/// Thread for ALF++ fuzzing process
/////////////////////////////////////////////////////////////////////////////////////////////////////////
void* PilotFuzzingProc (void *Para)
{
    BYTE* DriverDir = (BYTE *)Para;    
    BYTE Cmd[1024];

    snprintf (Cmd, sizeof (Cmd), "cd %s; ./run-fuzzer.sh -P 3", DriverDir);
    printf ("CMD: %s \r\n", Cmd);
    system (Cmd);
    
    return NULL;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////
/// Thread for dynamic event collection
/////////////////////////////////////////////////////////////////////////////////////////////////////////
void* DECollect (void *Para)
{
    PLServer *plSrv = (PLServer*)Para;

    DWORD QSize = QueueSize ();
    while (plSrv->FzExit == FALSE || QSize == 0)
    {
        QNode *QN = FrontQueue ();
        if (QN == NULL || QN->IsReady == FALSE)
        {
            QSize = QueueSize ();
            continue;
        }

        ObjValue *OV = (ObjValue *)QN->Buf;
        printf ("[QSize-%u]QUEUE: kEY:%u - Value:%u[type:%u, length:%u] \r\n", QSize, QN->TrcKey, (DWORD)OV->Value, OV->Type, OV->Length);

        OutQueue ();
        QSize = QueueSize ();
    }

    pthread_exit ((void*)0);
    return NULL;
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ple SERVER setup
/////////////////////////////////////////////////////////////////////////////////////////////////////////
#define AFL_PL_SOCKET_PORT   ("9999")
static inline DWORD SrvInit (PLServer *plSrv)
{
    plSrv->SockFd = socket(AF_INET, SOCK_DGRAM, 0);
    if(plSrv->SockFd < 0)
    {
        DEBUG ("Create socket fail....\r\n");
        return R_FAIL;
    }

    struct sockaddr_in addr_serv;
    int len;
    
    memset(&addr_serv, 0, sizeof(struct sockaddr_in));
    addr_serv.sin_family = AF_INET;
    addr_serv.sin_port   = htons((WORD)atoi(AFL_PL_SOCKET_PORT));
    addr_serv.sin_addr.s_addr = htonl(INADDR_ANY);
    len = sizeof(addr_serv);
    
    if(bind(plSrv->SockFd, (struct sockaddr *)&addr_serv, sizeof(addr_serv)) < 0)
    {
        DEBUG ("Bind socket to port[%d] fail....\r\n", plSrv->SockFd);
        return R_FAIL;
    }

    setenv ("AFL_PL_SOCKET_PORT", AFL_PL_SOCKET_PORT, 1);
    return R_SUCCESS;
}


static inline BYTE* Recv (PLServer *plSrv)
{
    memset (plSrv->SrvBuf, 0, sizeof(plSrv->SrvBuf));

    INT SkLen   = sizeof (struct sockaddr_in);
    INT RecvNum = recvfrom(plSrv->SockFd, plSrv->SrvBuf, sizeof(plSrv->SrvBuf), 
                           0, (struct sockaddr *)&plSrv->ClientAddr, (socklen_t *)&SkLen);
    assert (RecvNum != 0);

    return plSrv->SrvBuf;
}

static inline VOID Send (PLServer *plSrv, BYTE* Data, DWORD DataLen)
{
    INT SkLen   = sizeof (struct sockaddr_in);
    INT SendNum = sendto(plSrv->SockFd, Data, DataLen, 0, (struct sockaddr *)&plSrv->ClientAddr, SkLen);
    assert (SendNum != 0);

    return;
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////
/// Database management
/////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID InitDbTable (PLServer *plSrv)
{
    DWORD Ret;

    plSrv->DBSeedHandle       = DB_TYPE_SEED;
    plSrv->DBSeedBlockHandle  = DB_TYPE_SEED_BLOCK;
    plSrv->DBBrVariableHandle = DB_TYPE_BR_VARIABLE;

    InitDb(NULL);
    
    Ret = DbCreateTable(plSrv->DBSeedHandle, sizeof (Seed), 0);
    assert (Ret != R_FAIL);

    Ret = DbCreateTable(plSrv->DBSeedBlockHandle, sizeof (SeedBlock), FZ_SEED_NAME_LEN);
    assert (Ret != R_FAIL);

    Ret = DbCreateTable(plSrv->DBBrVariableHandle, sizeof (BrVariable), sizeof (DWORD));
    assert (Ret != R_FAIL);

    return;
}


static inline Seed* AddSeed (PLServer *plSrv, BYTE* SeedName)
{    
    DbReq Req;
    DbAck Ack;

    Req.dwDataType = plSrv->DBSeedHandle;
    Req.dwKeyLen   = 0;
    
    DWORD Ret = CreateDataNonKey (&Req, &Ack);
    assert (Ret == R_SUCCESS);

    Seed* Sn = (Seed*)(Ack.pDataAddr);
    strncpy (Sn->SName, SeedName, sizeof (Sn->SName));

    return Sn;
}


static inline SeedBlock* AddSeedBlock (PLServer *plSrv, Seed* CurSeed, MsgIB *MsgItr)
{    
    DbReq Req;
    DbAck Ack;
    BYTE SKey [FZ_SEED_NAME_LEN] = {0};

    Req.dwDataType = plSrv->DBSeedBlockHandle;
    Req.dwKeyLen   = FZ_SEED_NAME_LEN;

    snprintf (SKey, sizeof (SKey), "%s%u%u", CurSeed->SName, MsgItr->SIndex, MsgItr->Length);
    Req.pKeyCtx = SKey;
    
    DWORD Ret = CreateDataNonKey (&Req, &Ack);
    assert (Ret == R_SUCCESS);

    SeedBlock* SBlk = (SeedBlock*)(Ack.pDataAddr);

    return SBlk;
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////
/// Main logic of PLE server
/////////////////////////////////////////////////////////////////////////////////////////////////////////
static inline pthread_t CollectBrVariables (PLServer *plSrv)
{
    pthread_t Tid = 0;
    int Ret = pthread_create(&Tid, NULL, DECollect, plSrv);
    if (Ret != 0)
    {
        fprintf (stderr, "pthread_create for DECollect fail, Ret = %d\r\n", Ret);
        exit (0);
    }

    return Tid;
}

static inline DWORD GenSamplings (PLServer *plSrv, Seed* CurSeed, MsgIB *MsgItr)
{
    DWORD OFF = 0;
    for (DWORD Index = 0; Index < MsgItr->SampleNum; Index++)
    {
        ULONG SbVal = random ();
        DEBUG ("\t@@@@ [ple-sblk][%u]:%u\r\n", Index, (DWORD)SbVal);
                        
        switch (MsgItr->Length)
        {
            case 1:
            {
                BYTE *ValHdr = (BYTE*) (MsgItr + 1);
                ValHdr [Index] = (BYTE)SbVal;
                OFF += sizeof (BYTE);
                break;
            }
            case 2:
            {
                WORD *ValHdr = (WORD*) (MsgItr + 1);
                ValHdr [Index] = (WORD)SbVal;
                OFF += sizeof (WORD);
                break;
            }
            case 4:
            {
                DWORD *ValHdr = (DWORD*) (MsgItr + 1);
                ValHdr [Index] = (DWORD)SbVal;
                OFF += sizeof (DWORD);
                break;
            }
            case 8:
            {
                ULONG *ValHdr = (ULONG*) (MsgItr + 1);
                ValHdr [Index] = (ULONG)SbVal;
                OFF += sizeof (ULONG);
                break;
            }
            default:
            {
                assert (0);
            }
        }
    }

    return OFF;
}

void SemanticLearning (BYTE* SeedDir, BYTE* DriverDir, DWORD SeedAttr)
{
    PLServer *plSrv = &g_plSrv;
    
    DWORD Ret = SrvInit (plSrv);
    assert (Ret == R_SUCCESS);

    InitDbTable (plSrv);   
    InitQueue(MEMMOD_SHARE);
    
    pthread_t Tid = 0;
    Ret = pthread_create(&Tid, NULL, PilotFuzzingProc, DriverDir);
    if (Ret != 0)
    {
        fprintf (stderr, "pthread_create fail, Ret = %d\r\n", Ret);
        return;
    }

    DWORD SrvState = SRV_S_INIT;
    MsgHdr *MsgH   = NULL;
    Seed *CurSeed  = NULL;
    DWORD IsExit   = FALSE;
    while (!IsExit)
    {
        switch (SrvState)
        {
            case SRV_S_INIT:
            {
                MsgH = (MsgHdr *) Recv(plSrv);
                assert (MsgH->MsgType == PL_MSG_STARTUP);
                DEBUG ("[ple-INIT] recv PL_MSG_STARTUP from Fuzzer...\r\n");

                /* change to SRV_S_STARTUP */
                SrvState = SRV_S_STARTUP;
                break;
            }
            case SRV_S_STARTUP:
            {
                MsgH = (MsgHdr *)plSrv->SrvBuf;
                MsgH->MsgType = PL_MSG_STARTUP;
                MsgH->MsgLen  = sizeof (MsgHdr);
                Send (plSrv, (BYTE*)MsgH, MsgH->MsgLen);
                DEBUG ("[ple-STARTUP] reply PL_MSG_STARTUP to Fuzzer and complete handshake...\r\n");

                /* change to SRV_S_SEEDRCV */
                SrvState = SRV_S_SEEDRCV;
                break;
            }
            case SRV_S_SEEDRCV:
            {
                MsgH = (MsgHdr *) Recv(plSrv);
                if (MsgH->MsgType == PL_MSG_FZ_FIN)
                {
                    SrvState = SRV_S_FIN;
                    break;
                }
                assert (MsgH->MsgType == PL_MSG_SEED);

                MsgSeed *MsgSd = (MsgSeed*) (MsgH + 1);
                BYTE* SeedPath = (BYTE*)(MsgSd + 1);

                CurSeed = AddSeed (plSrv, SeedPath);
                CurSeed->SeedCtx = ReadFile (CurSeed->SName, &CurSeed->SeedLen, SeedAttr);

                DEBUG ("[ple-SEEDRCV] recv PL_MSG_SEED: [%u]%s[%u]\r\n", MsgSd->SeedKey, SeedPath, CurSeed->SeedLen);
                
                SrvState = SRV_S_ITB;
                break;
            }
            case SRV_S_ITB:
            {
                assert (CurSeed != NULL);
                
                DWORD OFF = 0;
                MsgH = (MsgHdr *)plSrv->SrvBuf;
                MsgH->MsgType = PL_MSG_ITR_BEGIN;
                MsgH->MsgLen  = sizeof (MsgHdr) + sizeof (MsgIB);
                
                MsgIB *MsgItr = (MsgIB *) (MsgH + 1);
                while (OFF < CurSeed->SeedLen)
                {
                    MsgItr->SIndex = OFF;
                    MsgItr->Length = sizeof (DWORD);
                    MsgItr->SampleNum = FZ_SAMPLE_NUM;

                    /* generate samples by random */
                    OFF += GenSamplings (plSrv, CurSeed, MsgItr);                 
                    MsgH->MsgLen += MsgItr->SampleNum * MsgItr->Length;

                    /* before the fuzzing iteration, start the thread for collecting the branch variables */
                    plSrv->FzExit = FALSE;
                    pthread_t CbvThrId = CollectBrVariables (plSrv);

                    /* inform the fuzzer */
                    Send (plSrv, (BYTE*)MsgH, MsgH->MsgLen);
                    DEBUG ("[ple-ITB-SEND] send PL_MSG_ITR_BEGIN[len-%u]: %u\r\n", MsgH->MsgLen, OFF);

                    MsgHdr *MsgRecv = (MsgHdr *) Recv(plSrv);
                    assert (MsgH->MsgType == PL_MSG_ITR_BEGIN);
                    DEBUG ("[ple-ITB-RECV] recv PL_MSG_ITR_BEGIN[len-%u]: %u\r\n", MsgH->MsgLen, OFF);
                    plSrv->FzExit = TRUE;

                    VOID *TRet = NULL;
                    pthread_join (CbvThrId, &TRet);
                    
                }
                
                SrvState = SRV_S_ITE;
                break;
            }
            case SRV_S_ITE:
            {
                MsgH = (MsgHdr *)plSrv->SrvBuf;
                MsgH->MsgType = PL_MSG_ITR_END;
                MsgH->MsgLen  = sizeof (MsgHdr);
                Send (plSrv, (BYTE*)MsgH, MsgH->MsgLen);
                DEBUG ("[ple-ITE] send PL_MSG_ITR_END...\r\n");
                
                /* change to SRV_S_SEEDRCV, wait for next seed */
                SrvState = SRV_S_SEEDRCV;
                break;
            }
            case SRV_S_FIN:
            {
                DEBUG ("[ple-FIN] recv PL_MSG_FZ_FIN...\r\n");
                IsExit = TRUE;
                break;
            }
            default:
            {
                assert (0);
            }
        }
    }

    DEBUG ("[ple]SemanticLearning exit....\r\n");
    return;
}



