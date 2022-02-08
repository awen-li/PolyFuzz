

#ifdef __cplusplus
extern "C"{
#endif 


#include <sys/shm.h>
#include "Queue.h"
#include "Event.h"


EVENT_HANDLE AllocEvent ()
{
    QNode *Node = InQueue ();
    if (Node == NULL)
    {
        printf ("Queue Full\r\n");
        exit (0);
    }

    Node->IsReady = FALSE;
    return (EVENT_HANDLE)Node->Buf;
}


unsigned EncodeEvent (EVENT_HANDLE eh, unsigned Esize, unsigned Etype, unsigned Length, BYTE* Value)
{
    assert (Esize + Length + 4 < BUF_SIZE);
    BYTE* Ehead = eh + Esize;
    
    Ehead[Esize] = (BYTE)Etype;
    Esize += 1;
    
    *(WORD*)(Ehead + Esize) = (WORD)Length;
    Esize += 2;

    memcpy (Ehead+Esize, Value, Length);
    Esize += Length;
    
    return Esize;
}


#ifdef __cplusplus
}
#endif

