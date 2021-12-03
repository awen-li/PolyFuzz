
/***********************************************************
 * Author: Wen Li
 * Date  : 7/24/2020
 * Describe: Queue.h - FIFO Queue
 * History:
   <1> 7/24/2020 , create
************************************************************/
#ifndef _QUEUE_H_
#define _QUEUE_H_
#include "MacroDef.h"

#ifdef __cplusplus
extern "C"{
#endif 


#define  QUEUE_SIZE (16 * 1024)
#define  BUF_SIZE   (64)

typedef struct tag_QNode
{
    DWORD TrcKey;
    DWORD ThreadId;
    DWORD Flag;
    char QBuf [BUF_SIZE];
}QNode;

static inline QNode* QBUF2QNODE (BYTE *Qbuf)
{
    return (QNode*)(Qbuf - (sizeof (QNode)-BUF_SIZE));
}


typedef struct tag_Queue
{
    DWORD NodeNum;
    DWORD Hindex;
    DWORD Tindex;
    DWORD Exit;
    DWORD MaxNodeNum;

    process_lock_t InLock;  
}Queue;


void InitQueue (unsigned QueueNum);
QNode* InQueue (void);
QNode* FrontQueue (void);
void OutQueue (void);
DWORD QueueSize (void);
VOID DelQueue (void);
VOID QueueSetExit (void);
DWORD QueueGetExit (void);


#ifdef __cplusplus
}
#endif

#endif 
