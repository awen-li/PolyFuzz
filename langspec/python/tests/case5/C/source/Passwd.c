#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


static char* PWD[] = {"123456789aqazwsxerfvtgbyhnikjjdfldjfhkshjfgkshgkshgfkshfgkhdg",
                      "0000000000000000000000001111111111111111111111111111111111111222222222222222222222222222222",
                      "44444444444444444444444444444444444444444444444444444444555555555555555555555555555555555555555555555555555566666666666666666",
                      "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttthhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh",
                     };

char* PwManage_NativePwd (int Key)
{
    char Buf [128];

    if (Key >= 102760444 &&  Key < 102760888 )
    {
        memcpy (Buf, PWD[3], strlen (PWD[3]));
    }
    else
    {
        memcpy (Buf, PWD[0], strlen (PWD[0]));
    }

    return strdup (Buf);    
}



