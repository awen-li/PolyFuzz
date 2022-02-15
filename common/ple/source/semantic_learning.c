#include "ctrace/Event.h"
#include <pthread.h>
#include "db.h"
#include "Queue.h"
#include "pl_struct.h"

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
    memset (plSrv->SrvRecvBuf, 0, sizeof(plSrv->SrvRecvBuf));

    INT SkLen   = sizeof (struct sockaddr_in);
    INT RecvNum = recvfrom(plSrv->SockFd, plSrv->SrvRecvBuf, sizeof(plSrv->SrvRecvBuf), 
                           0, (struct sockaddr *)&plSrv->ClientAddr, (socklen_t *)&SkLen);
    assert (RecvNum != 0);

    return plSrv->SrvRecvBuf;
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
    plSrv->DBBrVarKeyHandle   = DB_TYPE_BR_VARIABLE_KEY;

    InitDb(NULL);
    
    Ret = DbCreateTable(plSrv->DBSeedHandle, sizeof (Seed), 0);
    assert (Ret != R_FAIL);

    Ret = DbCreateTable(plSrv->DBSeedBlockHandle, sizeof (SeedBlock), FZ_SEED_NAME_LEN);
    assert (Ret != R_FAIL);

    Ret = DbCreateTable(plSrv->DBBrVariableHandle, sizeof (BrVariable), FZ_SEED_NAME_LEN);
    assert (Ret != R_FAIL);

    Ret = DbCreateTable(plSrv->DBBrVarKeyHandle, sizeof (DWORD), sizeof (DWORD));
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
    BYTE SKey [FZ_SEED_NAME_LEN+32] = {0};

    Req.dwDataType = plSrv->DBSeedBlockHandle;
    Req.dwKeyLen = snprintf (SKey, sizeof (SKey), "%s-%u-%u", CurSeed->SName, MsgItr->SIndex, MsgItr->Length);
    Req.pKeyCtx  = SKey;
    
    DWORD Ret = CreateDataByKey (&Req, &Ack);
    assert (Ret == R_SUCCESS);

    SeedBlock* SBlk = (SeedBlock*)(Ack.pDataAddr);
    SBlk->Sd = CurSeed;

    DEBUG ("@@@ AddSeedBlock: %s \r\n", SKey);

    return SBlk;
}


static inline VOID AddBrVarKey (PLServer *plSrv, DWORD Key)
{    
    DbReq Req;
    DbAck Ack;
    DWORD Ret;

    Req.dwDataType = plSrv->DBBrVarKeyHandle;
    Req.dwKeyLen   = sizeof (DWORD);
    Req.pKeyCtx    = (BYTE*)&Key;

    Ret = QueryDataByKey(&Req, &Ack);
    if (Ret != R_SUCCESS)
    {
        Ret = CreateDataByKey (&Req, &Ack);
        assert (Ret == R_SUCCESS);

        DWORD *BrValKey = (DWORD*)(Ack.pDataAddr);
        *BrValKey = Key;
    }

    return;
}



static inline VOID AddBrVariable (PLServer *plSrv, DWORD Key, ObjValue *Ov)
{    
    DbReq Req;
    DbAck Ack;
    DWORD Ret;
    BYTE SKey [FZ_SEED_NAME_LEN+32] = {0};

    SeedBlock* SBlk = plSrv->CurSdBlk;

    Req.dwDataType = plSrv->DBBrVariableHandle;
    Req.dwKeyLen   = snprintf (SKey, sizeof (SKey), "%s-%u-%u-%x", SBlk->Sd->SName, SBlk->SIndex, SBlk->Length, Key);
    Req.pKeyCtx    = SKey;

    Ret = QueryDataByKey(&Req, &Ack);
    if (Ret != R_SUCCESS)
    {
        Ret = CreateDataByKey (&Req, &Ack);
        assert (Ret == R_SUCCESS);
    }

    BrVariable *BrVal = (BrVariable*)(Ack.pDataAddr);
    if (BrVal->ValNum < FZ_SAMPLE_NUM)
    {
        BrVal->Key  = Key;
        BrVal->Type = Ov->Type;
        BrVal->Value [BrVal->ValNum] = Ov->Value;
        BrVal->ValNum++;
    }

    //DEBUG ("AddBrVariable ->[BrVal:%p] Key:%s, ValNum:%u\r\n", BrVal, SKey, BrVal->ValNum);
    
    AddBrVarKey (plSrv, Key);
    
    return;
}


static inline BYTE* GetDataByID (DWORD DataType, DWORD DataID)
{
    DbReq QueryReq;
    DbAck QueryAck;

    QueryReq.dwDataType = DataType;
    QueryReq.dwDataId   = DataID;
    DWORD Ret = QueryDataByID(&QueryReq, &QueryAck);
    assert (Ret != R_FAIL);

    return QueryAck.pDataAddr;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////
/// Thread for dynamic event collection
/////////////////////////////////////////////////////////////////////////////////////////////////////////
void* DECollect (void *Para)
{
    PLServer *plSrv = (PLServer*)Para;

    DWORD QSize = QueueSize ();
    DWORD Num = 0;
    while (plSrv->FzExit == FALSE || QSize != 0)
    {
        QNode *QN = FrontQueue ();
        if (QN == NULL || QN->IsReady == FALSE)
        {
            QSize = QueueSize ();
            continue;
        }

        ObjValue *OV = (ObjValue *)QN->Buf;

        AddBrVariable (plSrv, QN->TrcKey, OV);

        //DEBUG ("[%u][QSize-%u]QUEUE: KEY:%u - [type:%u, length:%u]Value:%lu \r\n", 
        //        Num , QSize, QN->TrcKey, (DWORD)OV->Type, (DWORD)OV->Length, OV->Value);

        OutQueue (QN);
        QSize = QueueSize ();
        Num ++;
    }
    
    printf ("DECollect loop over.....\r\n");
    pthread_exit ((void*)0);
}



/////////////////////////////////////////////////////////////////////////////////////////////////////////
/// Main logic of PLE server
/////////////////////////////////////////////////////////////////////////////////////////////////////////
static inline pthread_t CollectBrVariables (PLServer *plSrv)
{
    /* !!!! clear the queue: AFL++'s validation will cause redundant events */
    ClearQueue();
    
    pthread_t Tid = 0;
    int Ret = pthread_create(&Tid, NULL, DECollect, plSrv);
    if (Ret != 0)
    {
        fprintf (stderr, "pthread_create for DECollect fail, Ret = %d\r\n", Ret);
        exit (0);
    }

    return Tid;
}


static inline VOID LearningMain (PLServer *plSrv)
{
    DWORD SeedBlkNum = QueryDataNum (plSrv->DBSeedBlockHandle);
    DWORD VarKeyNum  = QueryDataNum (plSrv->DBBrVarKeyHandle);
    
    DEBUG ("SeedBlkNum = %u, VarKeyNum = %u \r\n", SeedBlkNum, VarKeyNum);
    for (DWORD DataId = 1; DataId <= SeedBlkNum; DataId++)
    {
        SeedBlock *SdBlk = (SeedBlock*) GetDataByID (plSrv->DBSeedBlockHandle, DataId);
        DEBUG ("[%u]%s-%u-%u \r\n", DataId, SdBlk->Sd->SName, SdBlk->SIndex, SdBlk->Length);
       
    }
    
    return;
}

static inline DWORD GenSamplings (PLServer *plSrv, Seed* CurSeed, MsgIB *MsgItr)
{
    SeedBlock* SBlk = AddSeedBlock (plSrv, CurSeed, MsgItr);
    assert (SBlk != NULL);
    SBlk->SIndex = MsgItr->SIndex;
    SBlk->Length = MsgItr->Length;
    plSrv->CurSdBlk = SBlk;
    
    DWORD OFF = 0;
    for (DWORD Index = 0; Index < MsgItr->SampleNum; Index++)
    {
        ULONG SbVal = random ();
        //DEBUG ("\t@@@@ [ple-sblk][%u]:%u\r\n", Index, (DWORD)SbVal);
                        
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

        SBlk->Value [Index] = SbVal;
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
                MsgH = (MsgHdr *)plSrv->SrvSendBuf;
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
                MsgH = (MsgHdr *)plSrv->SrvSendBuf;
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
                    DEBUG ("[ple-ITB-RECV] recv PL_MSG_ITR_BEGIN done[len-%u]: %u\r\n", MsgH->MsgLen, OFF);
                    plSrv->FzExit = TRUE;

                    VOID *TRet = NULL;
                    pthread_join (CbvThrId, &TRet);
                    
                }
                
                SrvState = SRV_S_ITE;
                break;
            }
            case SRV_S_ITE:
            {
                MsgH = (MsgHdr *)plSrv->SrvSendBuf;
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

    LearningMain (plSrv);
    
    DEBUG ("[ple]SemanticLearning exit....\r\n");
    DelQueue ();
    return;
}



