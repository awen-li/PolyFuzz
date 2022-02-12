#include <pthread.h>
#include "db.h"
#include "pl_struct.h"
#include "pl_message.h"

static PLServer g_plSrv;

BYTE* ReadFile (BYTE* SeedFile, DWORD *SeedLen, DWORD SeedAttr);
/////////////////////////////////////////////////////////////////////////////////////////////////////////
/// Control procedure
/////////////////////////////////////////////////////////////////////////////////////////////////////////
#define AFL_PL_SOCKET   (9999)
static inline DWORD SrvInit ()
{  
    PLServer *plSrv = &g_plSrv;
    
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
    addr_serv.sin_port   = htons(AFL_PL_SOCKET);
    addr_serv.sin_addr.s_addr = htonl(INADDR_ANY);
    len = sizeof(addr_serv);
    
    if(bind(plSrv->SockFd, (struct sockaddr *)&addr_serv, sizeof(addr_serv)) < 0)
    {
        DEBUG ("Bind socket to port[%d] fail....\r\n", plSrv->SockFd);
        return R_FAIL;
    }

    return R_SUCCESS;
}


static inline BYTE* Recv ()
{
    PLServer *plSrv = &g_plSrv;
    memset (plSrv->SrvBuf, 0, sizeof(plSrv->SrvBuf));

    INT SkLen   = sizeof (struct sockaddr_in);
    INT RecvNum = recvfrom(plSrv->SockFd, plSrv->SrvBuf, sizeof(plSrv->SrvBuf), 
                           0, (struct sockaddr *)&plSrv->ClientAddr, (socklen_t *)&SkLen);
    assert (RecvNum != 0);
    
    return plSrv->SrvBuf;
}

static inline VOID Send (BYTE* Data, DWORD DataLen)
{
    PLServer *plSrv = &g_plSrv;

    INT SkLen   = sizeof (struct sockaddr_in);
    INT SendNum = sendto(plSrv->SockFd, Data, DataLen, 0, (struct sockaddr *)&plSrv->ClientAddr, SkLen);
    assert (SendNum != 0);

    return;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////



/////////////////////////////////////////////////////////////////////////////////////////////////////////
/// Data exchange procedure
/////////////////////////////////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID InitDif (List* PluginList)
{
    DWORD Ret;
    PLServer *plSrv = &g_plSrv;

    plSrv->DBSeedHandle       = DB_TYPE_SEED;
    plSrv->DBSeedBlockHandle  = DB_TYPE_SEED_BLOCK;
    plSrv->DBBrVariableHandle = DB_TYPE_BR_VARIABLE;

    InitDb(NULL);
    
    Ret = DbCreateTable(plSrv->DBSeedHandle, sizeof (Seed), 0);
    assert (Ret != R_FAIL);

    Ret = DbCreateTable(plSrv->DBSeedBlockHandle, sizeof (SeedBLock), 0);
    assert (Ret != R_FAIL);

    Ret = DbCreateTable(plSrv->DBBrVariableHandle, sizeof (BrVariable), 0);
    assert (Ret != R_FAIL);

    return;
}


static inline VOID RunPilotFuzzing (BYTE* DriverDir)
{
    BYTE Cmd[1024];
    DWORD StartBB = 0;

    FILE *pf = fopen ("INTERAL_LOC", "r");
    if (pf != NULL)
    {
        fscanf (pf, "%u", &StartBB);
        fclose (pf);
    }

    if (StartBB != 0)
    {
        StartBB++;
        snprintf (Cmd, sizeof (Cmd), "cd %s; export AFL_START_BB=%u && ./run-fuzzer.sh -P 1", DriverDir, StartBB);
    }
    else
    {
        snprintf (Cmd, sizeof (Cmd), "cd %s; ./run-fuzzer.sh -P 1", DriverDir);
    }

    printf ("CMD: %s \r\n", Cmd);
    system (Cmd);
    return;
}


void* PilotFuzzingProc (void *Para)
{
    BYTE* DriverDir = (BYTE *)Para;
    
    while (1);
    
    return NULL;
}

static inline Seed* AddSeed (BYTE* SeedName)
{
    PLServer *plSrv = &g_plSrv;
    
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


void SemanticLearning (BYTE* SeedDir, BYTE* DriverDir, DWORD SeedAttr)
{
    DWORD Ret = SrvInit ();
    assert (Ret == R_SUCCESS);
    
    pthread_t Tid = 0;
    Ret = pthread_create(&Tid, NULL, PilotFuzzingProc, DriverDir);
    if (Ret != 0)
    {
        fprintf (stderr, "pthread_create fail, Ret = %d\r\n", Ret);
        return;
    }

    /* handshake, wait for Fuzzing startup*/
    BYTE MsgBuf[32];
    DWORD SrvState = SRV_S_INIT;
    MsgHdr *MsgH   = NULL;
    Seed *CurSeed  = NULL;
    while (1)
    {
        switch (SrvState)
        {
            case SRV_S_INIT:
            {
                MsgH = (MsgHdr *) Recv();
                assert (MsgH->MsgType == PL_MSG_STARTUP);
                DEBUG ("[INIT] recv PL_MSG_STARTUP from Fuzzer...\r\n");

                /* change to SRV_S_STARTUP */
                SrvState = SRV_S_STARTUP;
                break;
            }
            case SRV_S_STARTUP:
            {
                MsgH = (MsgHdr *)MsgBuf;
                MsgH->MsgType = PL_MSG_STARTUP;
                MsgH->MsgLen  = sizeof (MsgHdr);
                Send ((BYTE*)MsgH, MsgH->MsgLen);
                DEBUG ("[STARTUP] reply PL_MSG_STARTUP to Fuzzer and complete handshake...\r\n");

                /* change to SRV_S_SEEDRCV */
                SrvState = SRV_S_SEEDRCV;
                break;
            }
            case SRV_S_SEEDRCV:
            {
                MsgH = (MsgHdr *) Recv();
                assert (MsgH->MsgType == PL_MSG_SEED);

                BYTE* SeedPath = (BYTE *) (MsgH + 1);
                DEBUG ("[SEEDRCV] recv PL_MSG_SEED: %s\r\n", SeedPath);

                CurSeed = AddSeed (SeedPath);
                CurSeed->SeedCtx = ReadFile (CurSeed->SName, &CurSeed->SeedLen, SeedAttr);
                
                SrvState = SRV_S_ITB;
                break;
            }
            case SRV_S_ITB:
            {
                assert (CurSeed != NULL);
                
                DWORD OFF = 0;
                MsgH = (MsgHdr *)MsgBuf;
                MsgH->MsgType = PL_MSG_ITR_BEGIN;
                MsgH->MsgLen  = sizeof (MsgHdr) + sizeof (MsgIB);
                
                MsgIB *MsgItr = (MsgIB *) (MsgH + 1);
                while (OFF < CurSeed->SeedLen)
                {
                    MsgItr->SIndex = OFF;
                    MsgItr->Length = sizeof (DWORD);
                    Send ((BYTE*)MsgH, MsgH->MsgLen);
                    DEBUG ("[ITB-SEND] send PL_MSG_ITR_BEGIN: %u\r\n", OFF);

                    MsgHdr *MsgRecv = (MsgHdr *) Recv();
                    assert (MsgH->MsgType == PL_MSG_ITR_BEGIN);
                    DEBUG ("[ITB-RECV] recv PL_MSG_ITR_BEGIN: %u\r\n", OFF);

                    OFF += sizeof (DWORD);
                }
                
                SrvState = SRV_S_ITE;
                break;
            }
            case SRV_S_ITE:
            {
                MsgH = (MsgHdr *) Recv();
                assert (MsgH->MsgType == PL_MSG_ITR_END);
                DEBUG ("[ITE-SEND] recv PL_MSG_ITR_END...\r\n");
                
                /* change to SRV_S_SEEDRCV, wait for next seed */
                SrvState = SRV_S_SEEDRCV;
                break;
            }
            default:
            {
                assert (0);
            }
        }
    }
 
    return;
}



