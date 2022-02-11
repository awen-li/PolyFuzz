#include <pthread.h>
#include "pl_struct.h"

static PLServer g_plSrv;

/////////////////////////////////////////////////////////////////////////////////////////////////////////
/// Control procedure
/////////////////////////////////////////////////////////////////////////////////////////////////////////
#define AFL_PL_SOCKET   (9999)
static inline DWORD CtrlInit ()
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

    INT SkLen   = sizeof (struct sockaddr_in);
    INT RecvNum = recvfrom(plSrv->SockFd, plSrv->SrvBuf, sizeof(plSrv->SrvBuf), 
                           0, (struct sockaddr *)&plSrv->ClientAddr, (socklen_t *)&SkLen);
    assert (RecvNum != 0);
    plSrv->SrvBuf [RecvNum] = 0;
    
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


void SemanticLearning (BYTE* SeedDir, BYTE* DriverDir)
{
    DWORD Ret = CtrlInit ();
    assert (Ret == R_SUCCESS);
    
    pthread_t Tid = 0;
    Ret = pthread_create(&Tid, NULL, PilotFuzzingProc, DriverDir);
    if (Ret != 0)
    {
        fprintf (stderr, "pthread_create fail, Ret = %d\r\n", Ret);
        return;
    }
    
    /* main thread for pattern learning */
    while (1)
    {
    }

    
    return;
}



