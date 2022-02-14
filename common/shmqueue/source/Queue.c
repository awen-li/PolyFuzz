/***********************************************************
 * Author: Wen Li
 * Date  : 2/07/2022
 * Describe: FIFO Queue in shared memory
 * History:
   <1> 7/24/2020 , create
************************************************************/

#include <sys/shm.h>
#include "Queue.h"


/////////////////////////////////////////////////////////////////////////
// Lock definition
/////////////////////////////////////////////////////////////////////////
#define process_lock_t             pthread_rwlock_t
#define process_lock_init(x, attr) pthread_rwlock_init (x, attr) 
#define process_lock(x)            pthread_rwlock_rdlock (x) 
#define process_unlock(x)          pthread_rwlock_unlock (x)


/////////////////////////////////////////////////////////////////////////
// Queue Node mamagement
/////////////////////////////////////////////////////////////////////////
typedef struct _Queue_
{
    unsigned NodeNum;
    unsigned Hindex;
    unsigned Tindex;
    unsigned ExitFlag;

    unsigned MemMode;
    unsigned MaxNodeNum;
  
    process_lock_t QLock;
}Queue;


/////////////////////////////////////////////////////////////////////////
// Default parameters
/////////////////////////////////////////////////////////////////////////
#define DEFAULT_QUEUE_SIZE     (8092)
#define DEFAULT_SHARE_KEY      ("0xC3B3C5D0")
#define Q_2_NODELIST(Q)        (QNode *)(Q + 1)


/////////////////////////////////////////////////////////////////////////
// Debug info
/////////////////////////////////////////////////////////////////////////
#ifdef __DEBUG__
#define DEBUG(format, ...) printf("<shmQueue>" format, ##__VA_ARGS__)
#else
#define DEBUG(format, ...) 
#endif


/////////////////////////////////////////////////////////////////////////
// Global variables in local process
/////////////////////////////////////////////////////////////////////////
static Queue *g_Queue = NULL;
static int g_SharedId = 0;



static inline void* GetQueueMemory (MEMMOD MemMode, unsigned Size, char *ShareMemKey)
{
    void *MemAddr;
    
    if (MemMode == MEMMOD_SHARE)
    {
        key_t ShareKey = (key_t)strtol(ShareMemKey, NULL, 16);
        int SharedId = shmget(ShareKey, Size, 0666);
        if(SharedId == -1)
        {
            SharedId = shmget(ShareKey, Size, 0666|IPC_CREAT);
            assert (SharedId != -1);

            MemAddr = shmat(SharedId, 0, 0);
            assert (MemAddr != (void*)-1);

            memset (MemAddr, 0, Size);
        }
        else
        {
            MemAddr = shmat(SharedId, 0, 0);
            assert (MemAddr != (void*)-1);
        }

        g_SharedId = SharedId;
    }
    else
    {
        MemAddr = malloc (Size);
        assert (MemAddr != NULL);

        memset (MemAddr, 0, Size);
    }
    
    return MemAddr;
}


void InitQueue (unsigned QueueNum, char *ShareMemKey, MEMMOD MemMode)
{
    Queue* Q;

    if (g_Queue != NULL)
    {
        DEBUG ("@@@@@ Warning: Repeat comimg into InitQueue: %p-%u\r\n", g_Queue, g_SharedId);
        exit (0);
    }

    if (ShareMemKey == NULL)
    {
        ShareMemKey = DEFAULT_SHARE_KEY;
    }

    QueueNum = (QueueNum < DEFAULT_QUEUE_SIZE) ? DEFAULT_QUEUE_SIZE : QueueNum;
    unsigned Size = sizeof (Queue) + QueueNum * sizeof (QNode);
    
    Q = (Queue *)GetQueueMemory (MemMode, Size, ShareMemKey);
    if (Q->NodeNum == 0)
    {
        DEBUG ("@@@@@ start InitQueue[%u]\r\n", QueueNum);
        Q->NodeNum    = QueueNum;
        Q->MaxNodeNum = 0;
        Q->ExitFlag   = 0;
        Q->MemMode    = MemMode;

        pthread_rwlockattr_t LockAttr;
        pthread_rwlockattr_setpshared(&LockAttr, PTHREAD_PROCESS_SHARED);
        process_lock_init(&Q->QLock, &LockAttr);
    }

    g_Queue = Q;

    DEBUG ("InitQueue:[%p]-[%u] ShareMemKey = %s\r\n", Q, QueueNum, ShareMemKey);
    return;
}


QNode* InQueue ()
{
    if (g_Queue == NULL)
    {
        InitQueue (DEFAULT_QUEUE_SIZE, DEFAULT_SHARE_KEY, MEMMOD_SHARE);
        assert (g_Queue != NULL);
    }
    
    Queue* Q = g_Queue;
    QNode* Node = NULL;

    process_lock(&Q->QLock);
    if ((Q->Tindex+1) != Q->Hindex)
    {
        Node = Q_2_NODELIST(Q) + Q->Tindex++;
        Node->IsReady = 0;

        if (Q->Tindex >= Q->NodeNum)
        {
            Q->Tindex = 0;
        }
    }
    //DEBUG ("InQueue: [%p][%u, %u]/%u \r\n", Q, Q->Hindex, Q->Tindex, Q->NodeNum);
    process_unlock(&Q->QLock);
    
    return Node;
}

QNode* FrontQueue ()
{
    Queue* Q = g_Queue;
    if (Q == NULL)
    {
        return NULL;
    }

    QNode* Node = NULL;
    process_lock(&Q->QLock);
    if (Q->Hindex != Q->Tindex)
    {
        Node = (Q_2_NODELIST(Q) + Q->Hindex);
    }
    //DEBUG ("FrontQueue: [%p][%u, %u]/%u \r\n", Q, Q->Hindex,Q->Tindex, Q->NodeNum);
    process_unlock(&Q->QLock);
   
    return Node;
}



void OutQueue ()
{
    Queue* Q = g_Queue;
    if (Q == NULL)
    {
        return;
    }

    process_lock(&Q->QLock);
    //DEBUG ("OutQueue:[%p] [%u, %u]/%u\r\n", Q, Q->Hindex, Q->Tindex, Q->NodeNum);
    
    Q->Hindex++;
    if (Q->Hindex >= Q->NodeNum)
    {
        Q->Hindex = 0;
    }
    process_unlock(&Q->QLock);

    return;
}


unsigned QueueSize ()
{
    Queue* Q = g_Queue;
    if (Q == NULL)
    {
        return 0;
    }

    process_lock(&Q->QLock);
    unsigned Size = ((Q->Tindex + Q->NodeNum) - Q->Hindex)% Q->NodeNum;
    if (Size > Q->MaxNodeNum)
    {
        Q->MaxNodeNum = Size;
    }
    process_unlock(&Q->QLock);

    return Size;
}


void SetQueueExit ()
{
    Queue* Q = g_Queue;
    if (Q == NULL)
    {
        return;
    }

    process_lock(&Q->QLock);
    Q->ExitFlag = 1;
    process_unlock(&Q->QLock);
    DEBUG ("QueueSetExit: %u \r\n", Q->ExitFlag);

    return;
}

unsigned GetQueueExit ()
{
    Queue* Q = g_Queue;
    if (Q == NULL)
    {
        return 0;
    }

    unsigned Exit = 0;
    process_lock(&Q->QLock);
    Exit = Q->ExitFlag;
    process_unlock(&Q->QLock);

    return Exit;
}

void DelQueue ()
{
    if(g_SharedId == 0)
    {
        if (g_Queue != NULL)
        {
            free (g_Queue);
            g_Queue = NULL;
        }
    }
    else
    {
        if(shmdt(g_Queue) == -1)
        {
            printf("shmdt failed\n");
            return;
        }

        if(shmctl(g_SharedId, IPC_RMID, 0) == -1)
        {
            printf("shmctl(IPC_RMID) failed\n");
        }
    }

    return;
}


