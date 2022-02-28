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


static inline SeedBlock* AddSeedBlock (PLServer *plSrv, Seed* CurSeed, MsgIB *MsgItr)
{    
    DbReq Req;
    DbAck Ack;
    BYTE SKey [FZ_SEED_NAME_LEN+32] = {0};

    BYTE* SdName = GetSeedName (CurSeed->SName);

    Req.dwDataType = plSrv->DBSeedBlockHandle;
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



static inline VOID AddBrVariable (PLServer *plSrv, DWORD Key, ObjValue *Ov, DWORD QItr)
{    
    DbReq Req;
    DbAck Ack;
    DWORD Ret;
    BYTE SKey [FZ_SEED_NAME_LEN+32] = {0};

    SeedBlock* SBlk = plSrv->CurSdBlk;
    BYTE* SdName = GetSeedName (SBlk->Sd->SName);

    Req.dwDataType = plSrv->DBBrVariableHandle;
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
        BrVal->ValIndex++;
    }
    
    BrVal->Key  = Key;
    BrVal->Type = Ov->Type;
    BrVal->Value [BrVal->ValIndex] = Ov->Value;
    BrVal->ValideTag[BrVal->ValIndex] = TRUE;
    BrVal->ValIndex++;
    
    BrVal->ValNum++;

    DEBUG ("AddBrVariable ->[%u/%u][%u]Key:%s, Value:%u\r\n", (DWORD)BrVal->ValNum, (DWORD)BrVal->ValIndex, Key, SKey, (DWORD)Ov->Value);
    
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
    DWORD QItr  = 0;
    while (plSrv->FzExit == FALSE || QSize != 0)
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

            AddBrVariable (plSrv, QN->TrcKey, OV, QItr);

            DEBUG ("[%u][QSize-%u]QUEUE: KEY:%u - [type:%u, length:%u]Value:%lu \r\n", 
                    QItr , QSize, QN->TrcKey, (DWORD)OV->Type, (DWORD)OV->Length, OV->Value);
        }
        
        OutQueue (QN);
        QSize = QueueSize ();
        
    }
    
    printf ("DECollect loop over.....\r\n");
    pthread_exit ((void*)0);
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


static inline VOID MakeDir (BYTE *DirPath)
{
    struct stat st = {0};
    
    if (stat(DirPath, &st) == -1) 
    {
        mkdir(DirPath, 0777);
    }

    return;
}


static inline BYTE* GenAnalysicData (PLServer *plSrv, BYTE *BlkDir, SeedBlock *SdBlk, DWORD VarKey)
{
    static BYTE VarFile[128];
    DbReq Req;
    DbAck Ack;
    DWORD Ret;
    BYTE SKey [FZ_SEED_NAME_LEN] = {0};

    BYTE* SdName = GetSeedName (SdBlk->Sd->SName);

    Req.dwDataType = plSrv->DBBrVariableHandle;
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


static inline VOID GenSeed (PLServer *plSrv, BsValue *BsHeader, DWORD BlkNum, DWORD CurBlkNo, ULONG *CurSeed)
{
    for (DWORD Ei = 0; Ei < BsHeader->ValueNum ; Ei++)
    {
        CurSeed[CurBlkNo] = BsHeader->ValueList[Ei];
        if (CurBlkNo+1 == BlkNum)
        {
            plSrv->GenSeedNum++;

            snprintf (plSrv->NewSeedPath, sizeof (plSrv->NewSeedPath), "%s/%s_%u-%u", 
                      GEN_SEED, plSrv->CurSeedName, plSrv->CurAlign, plSrv->GenSeedNum);
            FILE *SF = fopen (plSrv->NewSeedPath, "w");
            assert (SF != NULL);
            
            DEBUG ("@@@ [%s]SEED: ", plSrv->NewSeedPath);
            for (DWORD si = 0; si < BlkNum; si++)
            {
                DEBUG ("%lu ", CurSeed[si]);
                switch (plSrv->CurAlign)
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
            GenSeed (plSrv, BsHeader+1, BlkNum, CurBlkNo+1, CurSeed);
        }
    }
}

static inline VOID GenAllSeeds (PLServer *plSrv, Seed *Sd)
{
    BYTE BlkDir[256];
    BYTE ALignDir[256];

    for (DWORD LIndex = 0; LIndex < plSrv->SeedBlockNum; LIndex++)
    {
        DWORD Align = plSrv->SeedBlock[LIndex];
        snprintf (ALignDir, sizeof (ALignDir), "%s/Align%u", plSrv->CurSeedName, Align);

        DWORD BlkNum  = 0;
        BsValue *SAList = (BsValue *) malloc (sizeof (BsValue) * (Sd->SeedLen/Align + 1));
        assert (SAList != NULL);

        DWORD LearnFailNum = 0;
        for (DWORD OFF = 0; OFF < Sd->SeedLen; OFF += Align)
        {
            BsValue *BsList = &SAList [BlkNum++];
            BsList->ValueList = NULL;
            BsList->ValueCap = BsList->ValueNum = 0;
            
            snprintf (BlkDir, sizeof (BlkDir), "%s/Align%u/BLK-%u-%u", plSrv->CurSeedName, Align, OFF, Align);
            ReadBsList (BlkDir, BsList);
            DEBUG ("@@@ [%u-%u] read value total of %u \r\n", OFF, Align, BsList->ValueNum);

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
            printf ("@@@ [%s]blocknum:%u, learning fails...!\r\n", plSrv->CurSeedName, Sd->SeedLen/Align);        
        }
        else
        {
            ULONG *CurSeed = (ULONG *) malloc (BlkNum * sizeof (ULONG));
            assert (CurSeed != NULL);
            memset (CurSeed, 0, BlkNum * sizeof (ULONG));

            plSrv->CurAlign = Align;
            GenSeed (plSrv, SAList, BlkNum, 0, CurSeed);
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

static inline ThrData* RequirThrRes (PLServer *plSrv)
{
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


static inline VOID WaitForTraining (ThrResrc *LnRes)
{
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
    snprintf (Cmd, sizeof (Cmd), "python -m regrnl %s", Td->TrainFile);
    DEBUG ("TrainingThread -> %s \r\n", Cmd);
    system (Cmd);

    RenderThrRes (Td);
}


static inline VOID StartTraining (PLServer *plSrv, BYTE *DataFile, SeedBlock *SdBlk)
{
    ThrData *Td = RequirThrRes(plSrv);
    strncpy (Td->TrainFile, DataFile, sizeof (Td->TrainFile));
    memcpy (&Td->SdBlk, SdBlk, sizeof (SeedBlock));

    
    pthread_t Tid = 0;
    int Ret = pthread_create(&Tid, NULL, TrainingThread, Td);
    if (Ret != 0)
    {
        fprintf (stderr, "pthread_create for training fail, Ret = %d\r\n", Ret);
        exit (0);
    }

    return;
}

static inline VOID LearningMain (PLServer *plSrv)
{
    BYTE BlkDir[256];
    BYTE ALignDir[256];
    DWORD SeedNum = QueryDataNum (plSrv->DBSeedHandle);
    DWORD SeedBlkNum = QueryDataNum (plSrv->DBSeedBlockHandle);
    DWORD VarKeyNum  = QueryDataNum (plSrv->DBBrVarKeyHandle);
    
    DEBUG ("SeedNum = %u, SeedBlkNum = %u, VarKeyNum = %u \r\n", SeedNum, SeedBlkNum, VarKeyNum);
    for (DWORD SdId = 1; SdId <= SeedNum; SdId++)
    {
        Seed *Sd = (Seed*) GetDataByID (plSrv->DBSeedHandle, SdId);
        DEBUG ("SEED[%u]%s-[%u] \r\n", SdId, Sd->SName, Sd->SeedLen);

        BYTE* SdName = GetSeedName(Sd->SName);
        MakeDir (SdName);
        plSrv->CurSeedName = SdName;
        DEBUG ("\tSEED-name:%s \r\n", SdName);

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
                DWORD VarKey = *(DWORD*) GetDataByID (plSrv->DBBrVarKeyHandle, KeyId);
                BYTE *DataFile = GenAnalysicData (plSrv, BlkDir, SdBlk, VarKey);
                if (DataFile == NULL)
                {
                    continue;
                }
                DEBUG ("\t@@@ VarKey: %x - %u -> %s\r\n", VarKey, VarKey, DataFile);

                ///// training proc here
                StartTraining (plSrv, DataFile, SdBlk);
            }

            SdBlkNo++;
            SbHdr = SbHdr->Nxt;
        }

        WaitForTraining (&plSrv->LearnThrs);

        MakeDir(GEN_SEED);
        GenAllSeeds (plSrv, Sd);
        ListDel(&Sd->SdBlkList, NULL);
    }

    return;
}

static inline VOID GenSamplings (PLServer *plSrv, Seed* CurSeed, MsgIB *MsgItr)
{
    SeedBlock* SBlk = AddSeedBlock (plSrv, CurSeed, MsgItr);
    assert (SBlk != NULL);
    SBlk->SIndex = MsgItr->SIndex;
    SBlk->Length = MsgItr->Length;
    plSrv->CurSdBlk = SBlk;
    
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

    ThrResrc *LearnThrs = &plSrv->LearnThrs;
    memset (LearnThrs, 0, sizeof (ThrResrc));
    mutex_lock_init (&LearnThrs->RnLock);
    LearnThrs->RequiredNum = 0;
    
    memset (plSrv->SeedBlock, 0, sizeof (plSrv->SeedBlock));
    plSrv->SeedBlockNum = 0;
    DWORD Bits = plSrv->PLOP.SdPattBits;
    if (Bits == 0)
    {
        plSrv->SeedBlock[plSrv->SeedBlockNum++] = 1;
        plSrv->SeedBlock[plSrv->SeedBlockNum++] = 2;
        plSrv->SeedBlock[plSrv->SeedBlockNum++] = 4;
        plSrv->SeedBlock[plSrv->SeedBlockNum++] = 8;
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

            DEBUG ("Add seed partition: %u\r\n", Patt);
            plSrv->SeedBlock[plSrv->SeedBlockNum++] = Patt;
            Bits = Bits/10;
        }
    }    
    plSrv->GenSeedNum = 0;
    
    DWORD Ret = SrvInit (plSrv);
    assert (Ret == R_SUCCESS);

    InitDbTable (plSrv);   
    InitQueue(MEMMOD_SHARE);

    return;
}

void SemanticLearning (BYTE* SeedDir, BYTE* DriverDir, PLOption *PLOP)
{
    PLServer *plSrv = &g_plSrv;
    PLInit (plSrv, PLOP);
    
    pthread_t Tid = 0;
    DWORD Ret = pthread_create(&Tid, NULL, PilotFuzzingProc, DriverDir);
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

                /* !!!! clear the queue: AFL++'s validation will cause redundant events */
                ClearQueue();

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
                CurSeed->SeedCtx = ReadFile (CurSeed->SName, &CurSeed->SeedLen, plSrv->PLOP.SdType);

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
                MsgItr->SampleNum = FZ_SAMPLE_NUM;

                for (DWORD LIndex = 0; LIndex < plSrv->SeedBlockNum; LIndex++)
                {
                    MsgItr->Length = plSrv->SeedBlock[LIndex];
                    if (MsgItr->Length > CurSeed->SeedLen)
                    {
                        continue;
                    }
                    
                    OFF = 0;
                    while (OFF < CurSeed->SeedLen)
                    {               
                        MsgItr->SIndex = OFF;
                        
                        /* generate samples by random */
                        GenSamplings (plSrv, CurSeed, MsgItr);
                        OFF += MsgItr->Length;
                        MsgH->MsgLen += MsgItr->SampleNum * MsgItr->Length;

                        /* before the fuzzing iteration, start the thread for collecting the branch variables */
                        plSrv->FzExit = FALSE;
                        pthread_t CbvThrId = CollectBrVariables (plSrv);

                        /* inform the fuzzer */
                        Send (plSrv, (BYTE*)MsgH, MsgH->MsgLen);
                        DEBUG ("[ple-ITB-SEND] send PL_MSG_ITR_BEGIN[len-%u]: %u[%u]\r\n", MsgH->MsgLen, OFF, CurSeed->SeedLen);

                        MsgHdr *MsgRecv = (MsgHdr *) Recv(plSrv);
                        assert (MsgH->MsgType == PL_MSG_ITR_BEGIN);
                        DEBUG ("[ple-ITB-RECV] recv PL_MSG_ITR_BEGIN done[len-%u]: %u[%u]\r\n", MsgH->MsgLen, OFF, CurSeed->SeedLen);
                        plSrv->FzExit = TRUE;

                        VOID *TRet = NULL;
                        pthread_join (CbvThrId, &TRet);
                        
                    }
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

    printf ("[ple]SemanticLearning exit, Learned seeds: %u....\r\n", plSrv->GenSeedNum);
    DelQueue ();
    close (plSrv->SockFd);
    DelDb();
    return;
}



