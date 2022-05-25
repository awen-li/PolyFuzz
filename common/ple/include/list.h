/***********************************************************
 * Author: Wen Li
 * Date  : 9/01/2020
 * Describe: List.h - A FIFO list for data management 
 * History:
   <1> 9/01/2020 , create
************************************************************/
#ifndef __LIST_H__
#define __LIST_H__
#include "macro.h"

#define HEAP_ALLOC (0xbfafcfdf)

typedef struct tag_LNode
{
    VOID *Data;
    struct tag_LNode *Nxt;
    struct tag_LNode *Pre;
}LNode;

typedef struct tag_List
{
    LNode *Header;
    LNode *Tail;

    DWORD NodeNum;
    DWORD HeapAlloc;
}List;

VOID ListInsert (List *L, VOID *N);
VOID ListRemove (List *L, LNode *N);
List* ListAllot ();

typedef BOOL (*CompData) (VOID *Ldata, VOID *Target);
typedef VOID (*ProcData) (VOID *Data);
typedef VOID (*DelData) (VOID *Data);

VOID ListVisit (List *L, ProcData Proc);
VOID ListDel (List *L, DelData Del);
BOOL IsInList (List *L, CompData Proc, VOID *Data);
VOID* ListSearch (List *L, CompData Proc, VOID *Data);


#endif 
