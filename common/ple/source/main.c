#include "syntax_learning.h"

static inline VOID  PLEmain (BYTE *SeedDir, BYTE * DriverDir)
{
    /* 1. learning the syntax  pattern */
    SyntaxLearning(DriverDir);


    return;
}

static inline VOID FormatPath (BYTE *Path)
{
    DWORD Len = strlen (Path);
    assert (Len != 0);
    
    if (Path[Len-1] == '/')
    {
        Path[Len-1] = 0;
    }

    return;
}

int main(int argc, char *argv[])
{
    BYTE *SeedDir   = NULL;
    BYTE *DriverDir = NULL;
    
    SDWORD Opt = 0;
    while ((Opt = getopt(argc, argv, "s:d:")) > 0) 
    {
        switch (Opt) 
        {
            case 's':
            {
                SeedDir = (BYTE *)strdup (optarg);
                assert (SeedDir != NULL);
                FormatPath (SeedDir);
                break;
            }
            case 'd':
            {
                DriverDir = (BYTE *)strdup (optarg);
                assert (DriverDir != NULL);
                FormatPath (DriverDir);
                break;
            }
            default:
            {
                break;
            }

        } 
    }

    if (SeedDir == NULL || DriverDir == NULL)
    {
        printf ("!!!ERROR: the Input SeedDir = %p, DriverDir = %p! \r\n", SeedDir, DriverDir);
        return 0;
    }

    PLEmain (SeedDir, DriverDir);

    free (SeedDir);
    free (DriverDir);
    return 0;
}
