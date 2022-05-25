#include <stdio.h>
#include <stdlib.h>

unsigned Getpasswd (unsigned char Key)
{
    unsigned Pwd;
    switch (Key)
    {
        case 4:
        {
            Pwd = (3 << ((random ()%4))) | (4 << ((random ()%2)));
            break;
        }
        case 8:
        {
            Pwd = (2 << ((random ()%8))) | (3 << ((random ()%4))) | (4 << ((random ()%2)));
            break;
        }
        case 16:
        {
            Pwd = (1 << (random ()%16)) | (2 << ((random ()%8))) | (3 << ((random ()%4))) | (4 << ((random ()%2)));
            break;            
        }
        default:
        {
            Pwd = Key << 3;
        }
    }

    return Pwd;
}





