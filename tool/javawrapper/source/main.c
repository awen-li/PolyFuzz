#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include "DynTrace.h"

static inline unsigned GetExtLoc ()
{
    unsigned ExtLocNum = 0;
    
    FILE *F = fopen ("EXTERNAL_LOC", "w");
    if (F == NULL)
    {
        printf ("[javawrapper]Please provide the file EXTERNAL_LOC.... \r\n");
        exit (0);    
    }

    int Ret = fscanf (F, "%u", &ExtLocNum);
    if (Ret == 0)
    {
        printf ("[javawrapper] read EXTERNAL_LOC fail\r\n");
        exit (0);
    }
    printf ("[javawrapper] Get EXTERNAL_LOC = %u \r\n", ExtLocNum);

    fclose (F);
    return ExtLocNum;
}


int main(int argc, char *argv[])
{
    if (argc <= 3)
    {
        printf ("[javawrapper]No java cmdline? \r\n");
        exit (0);
    }

    unsigned ExtLoc = GetExtLoc ();
    if (ExtLoc == 0)
    {
        ExtLoc = 256; /* default */
    }
    
    DynTraceInit (ExtLoc);

    char Cmd[1024] = {0};
    int cn = 1;
    while (argv[cn] != NULL)
    {
        strncat (Cmd, argv[cn], sizeof (Cmd));
        strncat (Cmd, " ", sizeof (Cmd));
        cn++;
    }

    int Ret = system (Cmd);
    if (Ret < 0)
    {
        return 1;
    }
    
    return 0;
}
