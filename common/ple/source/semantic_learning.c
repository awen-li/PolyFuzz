#include "ctrace/Event.h"
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include "db.h"
#include "Queue.h"
#include "pl_struct.h"

static PLServer g_plSrv;

BYTE* ReadFile (BYTE* SeedFile, DWORD *SeedLen, DWORD SeedAttr);
/////////////////////////////////////////////////////////////////////////////////////////////////////////
/// Thread for ALF++ fuzzing process
/////////////////////////////////////////////////////////////////////////////////////////////////////////
void* FuzzingProc (void *Para)
{
    BYTE* DriverDir = (BYTE *)Para;    
    BYTE Cmd[1024];

    snprintf (Cmd, sizeof (Cmd), "cd %s; ./run-fuzzer.sh -P 2", DriverDir);
    printf ("CMD: %s \r\n", Cmd);
    system (Cmd);
    
    return NULL;
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ple SERVER setup
/////////////////////////////////////////////////////////////////////////////////////////////////////////
#define AFL_PL_SOCKET_PORT   ("9999")
static inline DWORD SrvInit (SocketInfo *SkInfo)
{
    SkInfo->SockFd = socket(AF_INET, SOCK_DGRAM, 0);
    if(SkInfo->SockFd < 0)
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
    
    if(bind(SkInfo->SockFd, (struct sockaddr *)&addr_serv, sizeof(addr_serv)) < 0)
    {
        DEBUG ("Bind socket to port[%d] fail....\r\n", SkInfo->SockFd);
        return R_FAIL;
    }

    setenv ("AFL_PL_SOCKET_PORT", AFL_PL_SOCKET_PORT, 1);
    return R_SUCCESS;
}


static inline BYTE* Recv (SocketInfo *SkInfo)
{
    memset (SkInfo->SrvRecvBuf, 0, sizeof(SkInfo->SrvRecvBuf));

    INT SkLen   = sizeof (struct sockaddr_in);
    INT RecvNum = recvfrom(SkInfo->SockFd, SkInfo->SrvRecvBuf, sizeof(SkInfo->SrvRecvBuf), 
                           0, (struct sockaddr *)&SkInfo->ClientAddr, (socklen_t *)&SkLen);
    assert (RecvNum != 0);

    return SkInfo->SrvRecvBuf;
}

static inline VOID Send (SocketInfo *SkInfo, BYTE* Data, DWORD DataLen)
{
    INT SkLen   = sizeof (struct sockaddr_in);
    INT SendNum = sendto(SkInfo->SockFd, Data, DataLen, 0, (struct sockaddr *)&SkInfo->ClientAddr, SkLen);
    assert (SendNum != 0);

    return;
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////
/// Database management
/////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID InitDbTable (PLServer *plSrv)
{
    DWORD Ret;
    DbHandle *DHL = &plSrv->DHL;

    DHL->DBSeedHandle       = DB_TYPE_SEED;
    DHL->DBSeedBlockHandle  = DB_TYPE_SEED_BLOCK;
    DHL->DBBrVariableHandle = DB_TYPE_BR_VARIABLE;
    DHL->DBBrVarKeyHandle   = DB_TYPE_BR_VARIABLE_KEY;
    DHL->DBCacheBrVarHandle =  DB_TYPE_BR_VAR_CHACHE;

    InitDb(NULL);
    
    Ret = DbCreateTable(DHL->DBSeedHandle, 0, sizeof (Seed), 0);
    assert (Ret != R_FAIL);

    Ret = DbCreateTable(DHL->DBSeedBlockHandle, 128*1024, sizeof (SeedBlock), 48);
    assert (Ret != R_FAIL);

    Ret = DbCreateTable(DHL->DBBrVariableHandle, 128*1024, sizeof (BrVariable), 48);
    assert (Ret != R_FAIL);

    Ret = DbCreateTable(DHL->DBBrVarKeyHandle, 128*1024, sizeof (DWORD), sizeof (DWORD));
    assert (Ret != R_FAIL);

    Ret = DbCreateTable(DHL->DBCacheBrVarHandle, 8*1024, sizeof (BrVariable), 48);
    assert (Ret != R_FAIL);

    printf ("@InitDB: SeedTable[%u], SeedBlockTable[%u], BrVarTable[%u], BrVarKeyTable[%u], CacheBrVarTable[%u]\r\n",
            TableSize (DHL->DBSeedHandle), TableSize (DHL->DBSeedBlockHandle),
            TableSize (DHL->DBBrVariableHandle), TableSize (DHL->DBBrVarKeyHandle), 
            TableSize (DHL->DBCacheBrVarHandle));
    return;
}


static inline Seed* AddSeed (BYTE* SeedName)
{    
    DbReq Req;
    DbAck Ack;

    Req.dwDataType = DB_TYPE_SEED;
    Req.dwKeyLen   = 0;
    
    DWORD Ret = CreateDataNonKey (&Req, &Ack);
    assert (Ret == R_SUCCESS);

    Seed* Sn = (Seed*)(Ack.pDataAddr);
    strncpy (Sn->SName, SeedName, sizeof (Sn->SName));
    Sn->IsLearned = FALSE;

    return Sn;
}


static inline BYTE* GetSeedName (BYTE *SeedPath)
{
    /* id:000005 (,src:000001), time:0,orig:test-2 */
    static BYTE SdName[FZ_SEED_NAME_LEN];
    memset (SdName, 0, sizeof (SdName));

    BYTE* ID = strstr (SeedPath, "id:");
    assert (ID != NULL);
    strncpy (SdName, ID, 9);
    SdName[2] = '-';
    SdName[9] = '-';

    BYTE* ORG = strstr (SeedPath, "orig:");
    if (ORG == NULL)
    {
        ORG = strstr (SeedPath, "src:");
        assert (ORG != NULL);
        strncpy (SdName+10, ORG, 10);
        SdName[13] = '-';
    }
    else
    {
        strcat (SdName, ORG);
        SdName[14] = '-';
    }

    return SdName;
}


static inline SeedBlock* AddSeedBlock (PilotData *PD, Seed* CurSeed, MsgIB *MsgItr)
{    
    DbReq Req;
    DbAck Ack;
    BYTE SKey [FZ_SEED_NAME_LEN+32] = {0};

    BYTE* SdName = GetSeedName (CurSeed->SName);

    Req.dwDataType = PD->DHL->DBSeedBlockHandle;
    Req.dwKeyLen = snprintf (SKey, sizeof (SKey), "%s-%u-%u", SdName, MsgItr->SIndex, MsgItr->Length);
    Req.pKeyCtx  = SKey;

    DWORD Ret = QueryDataByKey(&Req, &Ack);
    if (Ret == R_SUCCESS)
    {
        return (SeedBlock*)(Ack.pDataAddr);
    }
    
    Ret = CreateDataByKey (&Req, &Ack);
    assert (Ret == R_SUCCESS);

    SeedBlock* SBlk = (SeedBlock*)(Ack.pDataAddr);
    SBlk->Sd = CurSeed;

    ListInsert(&CurSeed->SdBlkList, SBlk);

    DEBUG ("@@@ AddSeedBlock: %s \r\n", SKey);

    return SBlk;
}


static inline DWORD AddBrVarKey (PilotData *PD, DWORD Key)
{    
    DbReq Req;
    DbAck Ack;
    DWORD Ret;

    Req.dwDataType = PD->DHL->DBBrVarKeyHandle;
    Req.dwKeyLen   = sizeof (DWORD);
    Req.pKeyCtx    = (BYTE*)&Key;

    Ret = QueryDataByKey(&Req, &Ack);
    if (Ret != R_SUCCESS)
    {
        Ret = CreateDataByKey (&Req, &Ack);
        assert (Ret == R_SUCCESS);

        DWORD *BrValKey = (DWORD*)(Ack.pDataAddr);
        *BrValKey = Key;

        return TRUE;
    }
    else
    {
        return FALSE;
    }
}



static inline VOID CacheBrVar (PilotData *PD, DWORD Key, ObjValue *Ov, DWORD QItr)
{    
    DbReq Req;
    DbAck Ack;
    DWORD Ret;
    BYTE SKey [FZ_SEED_NAME_LEN+32] = {0};

    SeedBlock* SBlk = PD->CurSdBlk;
    BYTE* SdName = GetSeedName (SBlk->Sd->SName);

    Req.dwDataType = PD->DHL->DBCacheBrVarHandle;
    Req.dwKeyLen   = snprintf (SKey, sizeof (SKey), "%s-%u-%u-%x", SdName, SBlk->SIndex, SBlk->Length, Key);
    Req.pKeyCtx    = SKey;

    Ret = QueryDataByKey(&Req, &Ack);
    if (Ret != R_SUCCESS)
    {
        Ret = CreateDataByKey (&Req, &Ack);
        assert (Ret == R_SUCCESS);
    }

    BrVariable *BrVal = (BrVariable*)(Ack.pDataAddr);

    while (BrVal->ValIndex < QItr)
    {
        BrVal->ValideTag[BrVal->ValIndex] = FALSE;
        BrVal->ValIndex++;
    }

    /* In current implementation, we only save one value in an iteration */
    if (BrVal->ValIndex > QItr)
    {
        BrVal->ValIndex = QItr;
    }
    
    BrVal->Key  = Key;
    BrVal->Type = Ov->Type;
    BrVal->Value [BrVal->ValIndex] = Ov->Value;
    BrVal->ValideTag[BrVal->ValIndex] = TRUE;
    BrVal->ValIndex++;
    
    BrVal->ValNum++;

    DEBUG ("CacheBrVar ->[%u/%u][%u]Key:%s, Value:%u\r\n", (DWORD)BrVal->ValNum, (DWORD)BrVal->ValIndex, Key, SKey, (DWORD)Ov->Value);

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
static inline VOID IncLearnStat (PilotData *PD, DWORD BrNum)
{
    SeedBlock* SBlk = PD->CurSdBlk;

    DWORD LearnIndex = SBlk->SIndex/LEARN_BLOCK_SIZE;
    if (LearnIndex < LEARN_BLOCK_NUM)
    {
        PD->LearnStat[LearnIndex] += BrNum;
    }
    else
    {
        PD->LearnStat[LEARN_BLOCK_NUM-1] += BrNum;
    } 
}

static inline VOID ShowLearnStat (PilotData *PD)
{
    printf ("******************************  ShowLearnStat  ******************************\r\n");
    for (DWORD ix = 0; ix < LEARN_BLOCK_NUM; ix++)
    {
        DWORD Stat  = PD->LearnStat [ix];
        if (Stat == 0)
        {
            continue;
        }
        
        DWORD Start = ix * LEARN_BLOCK_SIZE;
        DWORD End   = Start + LEARN_BLOCK_SIZE;
        if (ix + 1 < LEARN_BLOCK_NUM)
        {
            printf ("\t[%-2u -> %-2u]: %u \r\n", Start, End, Stat);
        }
        else
        {
            printf ("\t[%-2u -> +++]: %u \r\n", Start, Stat);
        }
    }
    printf ("*****************************************************************************\r\n");
}


void* DECollect (void *Para)
{
    PilotData *PD   = (PilotData*)Para;
    DbHandle *DHL = PD->DHL;

    DWORD QSize = QueueSize ();
    DWORD QItr  = 0;
    DWORD BrKeyNum = 0;
    while (PD->FzExit == FALSE || QSize != 0)
    {
        QNode *QN = FrontQueue ();
        if (QN == NULL || QN->IsReady == FALSE)
        {
            QSize = QueueSize ();
            continue;
        }

        if (QN->TrcKey == TARGET_EXIT_KEY)
        {
            QItr ++;
            DEBUG ("##### [%u][QSize-%u]QUEUE: KEY:%x target exit and turn to next iteration.... \r\n", QItr, QSize, QN->TrcKey);
        }
        else
        {
            ObjValue *OV = (ObjValue *)QN->Buf;

            BrKeyNum += AddBrVarKey (PD, QN->TrcKey);

            CacheBrVar (PD, QN->TrcKey, OV, QItr);
            DEBUG ("[%u][QSize-%u]QUEUE: KEY:%u - [type:%u, length:%u]Value:%lu \r\n", 
                    QItr , QSize, QN->TrcKey, (DWORD)OV->Type, (DWORD)OV->Length, OV->Value);
        }
        
        OutQueue (QN);
        QSize = QueueSize ();
        
    }   
    DEBUG ("DECollect loop over.....\r\n");

    if (BrKeyNum == 0)
    {
        SeedBlock* SBlk = PD->CurSdBlk;
        DEBUG ("\t@@@DECollect --- [%s][%u-%u]No new branch varables captured....\r\n", 
               GetSeedName (SBlk->Sd->SName),
               SBlk->SIndex, SBlk->Length);
        ResetTable (DHL->DBCacheBrVarHandle);
    }
    else
    {
        CopyTable (DHL->DBBrVariableHandle, DHL->DBCacheBrVarHandle);
        printf ("\t@@@DECollect --- New BR found [to %u]. [Table%u] DataNum = %u after copy [Table%u][%u]! ---> Reset CacheBr to ",
                QueryDataNum(DHL->DBBrVarKeyHandle),
                DHL->DBBrVariableHandle, QueryDataNum(DHL->DBBrVariableHandle),
                DHL->DBCacheBrVarHandle, QueryDataNum(DHL->DBCacheBrVarHandle));
        
        ResetTable (DHL->DBCacheBrVarHandle);
        printf ("[%u] \r\n", TableSize(DHL->DBCacheBrVarHandle));

        IncLearnStat (PD, BrKeyNum);
    }
    pthread_exit ((void*)0);
}



/////////////////////////////////////////////////////////////////////////////////////////////////////////
/// Main logic of PLE server
/////////////////////////////////////////////////////////////////////////////////////////////////////////
static inline pthread_t CollectBrVariables (PilotData *PD)
{
    pthread_t Tid = 0;
    int Ret = pthread_create(&Tid, NULL, DECollect, PD);
    if (Ret != 0)
    {
        fprintf (stderr, "pthread_create for DECollect fail, Ret = %d\r\n", Ret);
        exit (0);
    }

    return Tid;
}


static inline VOID MakeDir (BYTE *DirPath)
{
    struct stat st = {0};
    
    if (stat(DirPath, &st) == -1) 
    {
        mkdir(DirPath, 0777);
    }

    return;
}


static inline BYTE* GenAnalysicData (PilotData *PD, BYTE *BlkDir, SeedBlock *SdBlk, DWORD VarKey)
{
    static BYTE VarFile[128];
    DbReq Req;
    DbAck Ack;
    DWORD Ret;
    BYTE SKey [FZ_SEED_NAME_LEN] = {0};

    BYTE* SdName = GetSeedName (SdBlk->Sd->SName);

    Req.dwDataType = PD->DHL->DBBrVariableHandle;
    Req.dwKeyLen   = snprintf (SKey, sizeof (SKey), "%s-%u-%u-%x", SdName, SdBlk->SIndex, SdBlk->Length, VarKey);
    Req.pKeyCtx    = SKey;
    Ret = QueryDataByKey(&Req, &Ack);
    if (Ret != R_SUCCESS)
    {
        DEBUG ("Query fail -> [BrVariable]: %s \r\n", SKey);
        return NULL;
    }
    BrVariable *BrVal = (BrVariable*)Ack.pDataAddr;

    /* FILE NAME */
    snprintf (VarFile, sizeof (VarFile), "%s/Var-%u.csv", BlkDir, VarKey);
    FILE *F = fopen (VarFile, "w");
    assert (F != NULL);

    fprintf (F, "SDBLK-%u-%u,BrVar-%u\n", SdBlk->SIndex, SdBlk->Length, VarKey);
    for (DWORD Index = 0; Index < FZ_SAMPLE_NUM; Index++)
    {
        if (BrVal->ValideTag[Index] != TRUE)
        {
            continue;
        }

        switch (BrVal->Type)
        {
            case VT_CHAR:
            {
                fprintf (F, "%u,%d\n", (DWORD)SdBlk->Value[Index], (SDWORD)BrVal->Value[Index]);
                break;
            }
            case VT_WORD:
            {
                fprintf (F, "%u,%d\n", (DWORD)SdBlk->Value[Index], (SDWORD)BrVal->Value[Index]);
                break;
            }
            case VT_DWORD:
            {
                fprintf (F, "%u,%d\n", (DWORD)SdBlk->Value[Index], (SDWORD)BrVal->Value[Index]);
                break;
            }
            case VT_LONG:
            {
                fprintf (F, "%u,%ld\n", (DWORD)SdBlk->Value[Index], (long)BrVal->Value[Index]);
                break;
            }
            default:
            {
                assert (0);
            }
        }  
    }
    fclose (F);
    
    return VarFile;    
}

static inline VOID ReadBsList (BYTE* BsDir, BsValue *BsList)
{
    DIR *Dir;
    struct dirent *SD;
    BYTE BSfPath[256];
    BYTE BSValStr[64];

    Dir = opendir((const char*)BsDir);
    if (Dir == NULL)
    {
        return;
    }

    List *FList = ListAllot();   
    while (SD = readdir(Dir))
    {
        if (strstr (SD->d_name, ".csv.bs") == NULL)
        {
            continue;
        }

        BYTE *Bsf = strdup (SD->d_name);
        ListInsert(FList, Bsf);
    }
    closedir (Dir);
    
    if (FList->NodeNum == 0)
    {
        return;
    }

    DWORD BaseNum = FList->NodeNum * 256;
    BsList->ValueList = (ULONG *)malloc (BaseNum * sizeof (ULONG));
    BsList->ValueCap  = BaseNum;
    BsList->ValueNum  = 0;
    assert (BsList->ValueList != NULL);

    LNode *LN = FList->Header;
    while (LN != NULL)
    {
        BYTE* FName = (BYTE *)LN->Data;
        snprintf (BSfPath, sizeof (BSfPath), "%s/%s", BsDir, FName);
        DEBUG ("### Get BSF: %s \r\n", BSfPath);

        FILE *BSF = fopen (BSfPath, "r");
        assert (BSF != NULL);

        while (!feof (BSF))
        {
            if (fgets (BSValStr, sizeof (BSValStr), BSF) != NULL)
            {
                DWORD i;
                ULONG Val = strtol(BSValStr, NULL, 10);
                for (i = 0; i < BsList->ValueNum; i++)
                {
                    if (BsList->ValueList[i] == Val)
                    {
                        break;
                    }
                }

                if (i < BsList->ValueNum)
                {
                    continue;
                }

                if (BsList->ValueNum >= BsList->ValueCap)
                {
                    DEBUG ("\t Realloc ValueList from %u to %u \r\n", BsList->ValueCap, BsList->ValueCap+BaseNum);
                    BsList->ValueCap  = BsList->ValueCap + BaseNum;
                    BsList->ValueList = (ULONG *)realloc (BsList->ValueList, BsList->ValueCap * sizeof (ULONG));
                    assert (BsList->ValueList != NULL);
                }

                BsList->ValueList[BsList->ValueNum] = Val;
                BsList->ValueNum++;
                DEBUG ("\t read value: %lu \r\n", Val);
            }
        }

        LN = LN->Nxt;
    }

    ListDel(FList, free);
    return;
}


static inline VOID GenSeed (PilotData *PD, BsValue *BsHeader, DWORD BlkNum, DWORD CurBlkNo, ULONG *CurSeed)
{
    for (DWORD Ei = 0; Ei < BsHeader->ValueNum ; Ei++)
    {
        CurSeed[CurBlkNo] = BsHeader->ValueList[Ei];
        if (CurBlkNo+1 == BlkNum)
        {
            PD->GenSeedNum++;

            snprintf (PD->NewSeedPath, sizeof (PD->NewSeedPath), "%s/%s_%u-%u", 
                      GEN_SEED, PD->CurSeedName, PD->CurAlign, PD->GenSeedNum);
            FILE *SF = fopen (PD->NewSeedPath, "w");
            assert (SF != NULL);
            
            DEBUG ("@@@ [%s]SEED: ", PD->NewSeedPath);
            for (DWORD si = 0; si < BlkNum; si++)
            {
                DEBUG ("%lu ", CurSeed[si]);
                switch (PD->CurAlign)
                {
                    case 1:
                    {
                        BYTE Val = (BYTE)CurSeed[si];
                        fwrite (&Val, sizeof (Val), 1, SF);
                        break;
                    }
                    case 2:
                    {
                        WORD Val = (WORD)CurSeed[si];
                        fwrite (&Val, sizeof (Val), 1, SF);
                        break;
                    }
                    case 4:
                    {
                        DWORD Val = (DWORD)CurSeed[si];
                        fwrite (&Val, sizeof (Val), 1, SF);
                        break;
                    }
                    case 8:
                    {
                        ULONG Val = (ULONG)CurSeed[si];
                        fwrite (&Val, sizeof (Val), 1, SF);
                        break;
                    }
                    default:
                    {
                        assert (0);
                    }
                }
            }
            DEBUG ("\r\n");

            fclose (SF);
        }
        else
        {      
            GenSeed (PD, BsHeader+1, BlkNum, CurBlkNo+1, CurSeed);
        }
    }
}

static inline VOID GenAllSeeds (PilotData *PD, Seed *Sd)
{
    BYTE BlkDir[256];
    BYTE ALignDir[256];

    PLOption *PLOP = PD->PLOP;

    for (DWORD LIndex = 0; LIndex < PLOP->SeedBlockNum; LIndex++)
    {
        DWORD Align = PLOP->SeedBlock[LIndex];
        snprintf (ALignDir, sizeof (ALignDir), "%s/Align%u", PD->CurSeedName, Align);

        DWORD BlkNum  = 0;
        BsValue *SAList = (BsValue *) malloc (sizeof (BsValue) * (Sd->SeedLen/Align + 1));
        assert (SAList != NULL);

        DWORD LearnFailNum = 0;
        for (DWORD OFF = 0; OFF < Sd->SeedLen; OFF += Align)
        {
            BsValue *BsList = &SAList [BlkNum++];
            BsList->ValueList = NULL;
            BsList->ValueCap = BsList->ValueNum = 0;

            if (OFF < PLOP->TryLength)
            {     
                snprintf (BlkDir, sizeof (BlkDir), "%s/Align%u/BLK-%u-%u", PD->CurSeedName, Align, OFF, Align);
                ReadBsList (BlkDir, BsList);
                DEBUG ("@@@ [%u-%u] read value total of %u \r\n", OFF, Align, BsList->ValueNum);
            }

            /* For this seed block, we learned nothing, using original value instead */
            if (BsList->ValueNum == 0)
            {
                LearnFailNum++;
                    
                BsList->ValueList = (ULONG *)malloc (sizeof (ULONG));
                *(ULONG*)BsList->ValueList = 0;
                BsList->ValueCap  = 1;
                assert (BsList->ValueList != NULL);
                memcpy (BsList->ValueList, Sd->SeedCtx+OFF, Align);
                BsList->ValueNum++;
            }
        }

        if (LearnFailNum == Sd->SeedLen/Align)
        {
            printf ("@@@GenAllSeeds [%s]blocknum:%u, learning fails...!\r\n", PD->CurSeedName, Sd->SeedLen/Align);        
        }
        else
        {
            ULONG *CurSeed = (ULONG *) malloc (BlkNum * sizeof (ULONG));
            assert (CurSeed != NULL);
            memset (CurSeed, 0, BlkNum * sizeof (ULONG));

            PD->CurAlign = Align;
            GenSeed (PD, SAList, BlkNum, 0, CurSeed);
            free (CurSeed);
        }

        while (BlkNum > 0)
        {
            free (SAList[--BlkNum].ValueList);        
        }
        free (SAList);   
    }
    
    return;
}

static inline ThrData* RequirThrRes ()
{
    PLServer *plSrv    = &g_plSrv;
    
    ThrResrc *LnRes = &plSrv->LearnThrs;
    DWORD RequiredThrs;
    ThrData* Td = NULL;
    
    while (TRUE)
    {
        mutex_lock (&LnRes->RnLock);
        if (LnRes->RequiredNum < plSrv->PLOP.LnThrNum)
        {
            Td = LnRes->TD;
            for (DWORD ix = 0; ix < plSrv->PLOP.LnThrNum; ix++)
            {
                if (Td->Status == 0)
                {
                    Td->Status = 1;
                    Td->LearnThrs = (BYTE *)LnRes;
                    break;
                }
            }
            LnRes->RequiredNum++;
        }
        else
        {
            Td = NULL;
        }
        mutex_unlock (&LnRes->RnLock);

        if (Td != NULL)
        {
            break;
        }

        sleep (1);
    }

    DEBUG ("@@@ RequirThrRes: RequiredNum=%u \r\n", LnRes->RequiredNum);
    return Td;
}


static inline VOID RenderThrRes (ThrData* Td)
{
    ThrResrc *LnRes = (ThrResrc *)Td->LearnThrs;
    mutex_lock (&LnRes->RnLock);
    Td->Status = 0;
    assert (LnRes->RequiredNum > 0);
    LnRes->RequiredNum--;
    mutex_unlock (&LnRes->RnLock);
    return;
}


static inline VOID WaitForTraining ()
{
    ThrResrc *LnRes = &g_plSrv.LearnThrs;
    DWORD RequiredThrs = 0;
    
    while (TRUE)
    {
        mutex_lock (&LnRes->RnLock);
        RequiredThrs = LnRes->RequiredNum;
        mutex_unlock (&LnRes->RnLock);

        if (RequiredThrs == 0)
        {
            break;
        }
        else
        {
            sleep (1);
        }
    }
    return;
}


void* TrainingThread (void *Para)
{
    BYTE Cmd[1024];

    ThrData *Td = (ThrData *)Para;
    if (Td->BvDir == NULL)
    {
        snprintf (Cmd, sizeof (Cmd), "python -m regrnl %s -d 0.35", Td->TrainFile);
    }
    else
    {
        snprintf (Cmd, sizeof (Cmd), "python -m regrnl -B %s %s -d 0.35", Td->BvDir, Td->TrainFile);
    }
    DEBUG ("TrainingThread -> %s \r\n", Cmd);
    system (Cmd);

    RenderThrRes (Td);
}


static inline VOID StartTraining (PilotData *PD, BYTE *DataFile, SeedBlock *SdBlk)
{
    ThrData *Td = RequirThrRes();
    printf (">>>[StartTraining] %s --- [%u-%u]\r\n", DataFile, SdBlk->SIndex, SdBlk->Length);
    
    strncpy (Td->TrainFile, DataFile, sizeof (Td->TrainFile));
    memcpy (&Td->SdBlk, SdBlk, sizeof (SeedBlock));
    Td->BvDir = PD->PLOP->BvDir;
    
    pthread_t Tid = 0;
    int Ret = pthread_create(&Tid, NULL, TrainingThread, Td);
    if (Ret != 0)
    {
        fprintf (stderr, "pthread_create for training fail, Ret = %d\r\n", Ret);
        exit (0);
    }

    return;
}

static inline VOID LearningMain (PilotData *PD)
{
    BYTE BlkDir[256];
    BYTE ALignDir[256];

    DbHandle *DHL = PD->DHL;
    DWORD SeedNum = QueryDataNum (DHL->DBSeedHandle);
    DWORD SeedBlkNum = QueryDataNum (DHL->DBSeedBlockHandle);
    DWORD VarKeyNum  = QueryDataNum (DHL->DBBrVarKeyHandle);
    
    DEBUG ("SeedNum = %u, SeedBlkNum = %u, VarKeyNum = %u \r\n", SeedNum, SeedBlkNum, VarKeyNum);
    for (DWORD SdId = 1; SdId <= SeedNum; SdId++)
    {
        Seed *Sd = (Seed*) GetDataByID (DHL->DBSeedHandle, SdId);
        if (Sd->IsLearned == TRUE)
        {
            continue;
        }

        BYTE* SdName = GetSeedName(Sd->SName);
        MakeDir (SdName);
        PD->CurSeedName = SdName;
        
        printf ("[LearningMain]SEED[ID-%u]%s-[length-%u] \r\n", SdId, SdName, Sd->SeedLen);

        DWORD SdBlkNo = 0;
        LNode *SbHdr  = Sd->SdBlkList.Header;
        while (SbHdr != NULL)
        {
            SeedBlock *SdBlk = (SeedBlock*)SbHdr->Data;

            snprintf (ALignDir, sizeof (ALignDir), "%s/Align%u", SdName, SdBlk->Length);
            MakeDir (ALignDir);
            
            snprintf (BlkDir, sizeof (BlkDir), "%s/Align%u/BLK-%u-%u", SdName, SdBlk->Length, SdBlk->SIndex, SdBlk->Length);
            MakeDir (BlkDir);
            DEBUG ("\t@@@ [%u]%s\r\n", SdBlkNo, BlkDir);

            for (DWORD KeyId = 1; KeyId <= VarKeyNum; KeyId++)
            {
                DWORD VarKey = *(DWORD*) GetDataByID (DHL->DBBrVarKeyHandle, KeyId);
                BYTE *DataFile = GenAnalysicData (PD, BlkDir, SdBlk, VarKey);
                if (DataFile == NULL)
                {
                    continue;
                }
                DEBUG ("\t@@@ VarKey: %x - %u -> %s\r\n", VarKey, VarKey, DataFile);

                ///// training proc here
                StartTraining (PD, DataFile, SdBlk);
            }

            SdBlkNo++;
            SbHdr = SbHdr->Nxt;
        }

        WaitForTraining ();

        MakeDir(GEN_SEED);
        GenAllSeeds (PD, Sd);
        ListDel(&Sd->SdBlkList, NULL);
        Sd->IsLearned = TRUE;
    }

    printf ("[ple]PilotMode exit, Learned seeds: %u....\r\n", PD->GenSeedNum);
    return;
}

static inline VOID GenSamplings (PilotData *PD, Seed* CurSeed, MsgIB *MsgItr)
{
    SeedBlock* SBlk = AddSeedBlock (PD, CurSeed, MsgItr);
    assert (SBlk != NULL);
    SBlk->SIndex = MsgItr->SIndex;
    SBlk->Length = MsgItr->Length;
    PD->CurSdBlk = SBlk;
    
    for (DWORD Index = 0; Index < MsgItr->SampleNum; Index++)
    {
        ULONG SbVal = random ()%256;
        //DEBUG ("\t@@@@ [ple-sblk][%u]:%u\r\n", Index, (DWORD)SbVal);
                        
        switch (MsgItr->Length)
        {
            case 1:
            {
                BYTE *ValHdr = (BYTE*) (MsgItr + 1);
                ValHdr [Index] = (BYTE)SbVal;
                break;
            }
            case 2:
            {
                WORD *ValHdr = (WORD*) (MsgItr + 1);
                ValHdr [Index] = (WORD)SbVal;
                break;
            }
            case 4:
            {
                DWORD *ValHdr = (DWORD*) (MsgItr + 1);
                ValHdr [Index] = (DWORD)SbVal;
                break;
            }
            case 8:
            {
                ULONG *ValHdr = (ULONG*) (MsgItr + 1);
                ValHdr [Index] = (ULONG)SbVal;
                break;
            }
            default:
            {
                assert (0);
            }
        }

        SBlk->Value [Index] = SbVal;
    }

    return;
}


VOID PLInit (PLServer *plSrv, PLOption *PLOP)
{
    memcpy (&plSrv->PLOP, PLOP, sizeof (PLOption));

    /* multi-thread init */
    ThrResrc *LearnThrs = &plSrv->LearnThrs;
    memset (LearnThrs, 0, sizeof (ThrResrc));
    mutex_lock_init (&LearnThrs->RnLock);
    LearnThrs->RequiredNum = 0;

    /* init seed block in PLOP */
    PLOP = &plSrv->PLOP;
    memset (PLOP->SeedBlock, 0, sizeof (PLOP->SeedBlock));
    PLOP->SeedBlockNum = 0;
    DWORD Bits = PLOP->SdPattBits;
    if (Bits == 0)
    {
        PLOP->SeedBlock[PLOP->SeedBlockNum++] = 1;
        PLOP->SeedBlock[PLOP->SeedBlockNum++] = 2;
        PLOP->SeedBlock[PLOP->SeedBlockNum++] = 4;
        PLOP->SeedBlock[PLOP->SeedBlockNum++] = 8;
    }
    else
    {
        while (Bits != 0)
        {
            DWORD Patt = Bits%10;
            if (Patt != 1 && Patt != 2 && Patt != 4 && Patt != 8)
            {
                fprintf (stderr, "SEED partition support [1,2,4,8]!!\r\n");
                exit (0);
            }

            printf ("[PLInit]Add seed partition: %u\r\n", Patt);
            PLOP->SeedBlock[PLOP->SeedBlockNum++] = Patt;
            Bits = Bits/10;
        }
    }

    /* init pilot data */
    PilotData *PD = &plSrv->PD;
    PD->GenSeedNum = 0;
    PD->SrvState   = SRV_S_STARTUP;
    PD->DHL        = &plSrv->DHL;
    PD->PLOP       = &plSrv->PLOP;
    
    /* init msg server */
    DWORD Ret = SrvInit (&plSrv->SkInfo);
    assert (Ret == R_SUCCESS);

    /* init DB */
    InitDbTable (plSrv);   

    /* init event queue */
    InitQueue(MEMMOD_SHARE);

    /* set default run-mode */
    plSrv->RunMode = RUNMOD_PILOT;

    return;
}


VOID PLDeInit (PLServer *plSrv)
{
    DelQueue ();
    close (plSrv->SkInfo.SockFd);
    DelDb();

    return;
}

static inline MsgHdr* FormatMsg (SocketInfo *SkInfo, DWORD MsgType)
{
    MsgHdr *MsgH;
    
    MsgH = (MsgHdr *)SkInfo->SrvSendBuf;
    MsgH->MsgType = MsgType;
    MsgH->MsgLen  = sizeof (MsgHdr);

    return MsgH;
}

static inline VOID SwitchMode (RUNMOD RunMode)
{
    PLServer *plSrv = &g_plSrv;
    plSrv->RunMode = RunMode;
    return;
}

static inline DWORD PilotMode (PilotData *PD, SocketInfo *SkInfo)
{
    Seed *CurSeed;
    MsgHdr *MsgRev;
    MsgHdr *MsgSend;
    PLOption *PLOP = PD->PLOP;

    switch (PD->SrvState)
    {
        case SRV_S_STARTUP:
        {
            MsgRev = (MsgHdr *) Recv(SkInfo);
            assert (MsgRev->MsgType == PL_MSG_STARTUP);
            printf ("[ple-INIT] recv PL_MSG_STARTUP from Fuzzer...\r\n");

            MsgSend = FormatMsg (SkInfo, PL_MSG_STARTUP);
            Send (SkInfo, (BYTE*)MsgSend, MsgSend->MsgLen);
            printf ("[ple-STARTUP] reply PL_MSG_STARTUP to Fuzzer and complete handshake...\r\n");

            /* !!!! clear the queue: AFL++'s validation will cause redundant events */
            ClearQueue();

            /* change to SRV_S_SEEDRCV */
            PD->SrvState = SRV_S_SEEDRCV;
            break;
        }
        case SRV_S_SEEDRCV:
        {
            MsgRev = (MsgHdr *) Recv(SkInfo);
            if (MsgRev->MsgType == PL_MSG_FZ_FIN)
            {
                PD->SrvState = SRV_S_FIN;
                break;
            }
            assert (MsgRev->MsgType == PL_MSG_SEED);
    
            MsgSeed *MsgSd = (MsgSeed*) (MsgRev + 1);
            BYTE* SeedPath = (BYTE*)(MsgSd + 1);
    
            CurSeed = AddSeed (SeedPath);
            CurSeed->SeedCtx = ReadFile (CurSeed->SName, &CurSeed->SeedLen, PLOP->SdType);
            PD->CurSeed = CurSeed;
    
            printf ("[ple-SEEDRCV] recv PL_MSG_SEED: [%u]%s[%u]\r\n", MsgSd->SeedKey, SeedPath, CurSeed->SeedLen);
                    
            PD->SrvState = SRV_S_ITB;
            break;
        }
        case SRV_S_ITB:
        {
            CurSeed = PD->CurSeed;
            assert (CurSeed != NULL);
            
            MsgSend = FormatMsg(SkInfo, PL_MSG_ITR_BEGIN);
            MsgIB *MsgItr = (MsgIB *) (MsgSend + 1);
            MsgItr->SampleNum = FZ_SAMPLE_NUM;

            DWORD OFF = 0;
            DWORD TryLength = (PLOP->TryLength < CurSeed->SeedLen) 
                              ? PLOP->TryLength
                              : CurSeed->SeedLen;
            for (DWORD LIndex = 0; LIndex < PLOP->SeedBlockNum; LIndex++)
            {
                MsgItr->Length = PLOP->SeedBlock[LIndex];
                if (MsgItr->Length > TryLength)
                {
                    continue;
                }
                        
                OFF = 0;
                while (OFF < TryLength)
                {               
                    MsgItr->SIndex = OFF;
                    MsgSend->MsgLen  = sizeof (MsgHdr) + sizeof (MsgIB);
                            
                    /* generate samples by random */
                    GenSamplings (PD, CurSeed, MsgItr);
                    OFF += MsgItr->Length;
                    MsgSend->MsgLen += MsgItr->SampleNum * MsgItr->Length;
    
                    /* before the fuzzing iteration, start the thread for collecting the branch variables */
                    PD->FzExit = FALSE;
                    pthread_t CbvThrId = CollectBrVariables (PD);
    
                    /* inform the fuzzer */
                    Send (SkInfo, (BYTE*)MsgSend, MsgSend->MsgLen);
                    DEBUG ("[ple-ITB-SEND] send PL_MSG_ITR_BEGIN[MSG-LEN:%u]: OFF:%u[SEED-LEN:%u]\r\n", MsgSend->MsgLen, OFF, TryLength);
    
                    MsgHdr *MsgRecv = (MsgHdr *) Recv(SkInfo);
                    assert (MsgSend->MsgType == PL_MSG_ITR_BEGIN);
                    DEBUG ("[ple-ITB-RECV] recv PL_MSG_ITR_BEGIN done[MSG-LEN:%u]: OFF:%u[SEED-LEN:%u]\r\n", MsgSend->MsgLen, OFF, TryLength);
                    PD->FzExit = TRUE;
    
                    VOID *TRet = NULL;
                    pthread_join (CbvThrId, &TRet);
                            
                }
            }
                    
            PD->SrvState = SRV_S_ITE;
            break;
        }
        case SRV_S_ITE:
        {
            MsgSend = FormatMsg(SkInfo, PL_MSG_ITR_END);
            Send (SkInfo, (BYTE*)MsgSend, MsgSend->MsgLen);
            DEBUG ("[ple-ITE] send PL_MSG_ITR_END...\r\n");
                    
            ShowLearnStat (PD);
                    
            /* change to SRV_S_SEEDRCV, wait for next seed */
            PD->SrvState = SRV_S_SEEDRCV;
            break;
        }
        case SRV_S_FIN:
        {
            DEBUG ("[ple-FIN] recv PL_MSG_FZ_FIN...\r\n");
            LearningMain (PD);
            SwitchMode (RUNMOD_OFFICIAL);
            break;
        }
        default:
        {
            assert (0);
        }
    }

    return FALSE;
}


static inline DWORD StandardMode (StanddData *SD, SocketInfo *SkInfo)
{
    printf ("Entry OfficialMode...\r\n");
    sleep (1);
    return FALSE;
}


VOID SemanticLearning (BYTE* SeedDir, BYTE* DriverDir, PLOption *PLOP)
{
    PLServer *plSrv    = &g_plSrv;
    SocketInfo *SkInfo = &plSrv->SkInfo;
    
    PLInit (plSrv, PLOP);
    
    pthread_t Tid = 0;
    DWORD Ret = pthread_create(&Tid, NULL, FuzzingProc, DriverDir);
    if (Ret != 0)
    {
        fprintf (stderr, "pthread_create fail, Ret = %d\r\n", Ret);
        return;
    }
    
    DWORD IsExit   = FALSE;
    while (!IsExit)
    {
        switch (plSrv->RunMode)
        {
            case RUNMOD_PILOT:
            {
                IsExit = PilotMode (&plSrv->PD, SkInfo);
                break;
            }
            case RUNMOD_OFFICIAL:
            {
                IsExit = StandardMode (&plSrv->SD, SkInfo);
                break;
            }
            default:
            {
                assert (0);
            }
        }
    }

    PLDeInit (plSrv);
    return;
}



