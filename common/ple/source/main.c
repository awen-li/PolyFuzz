#include "pl_learning.h"


static inline VOID  PLEmain (BYTE *SeedDir, BYTE * DriverDir, DWORD SeedAttr)
{
    /* 1. learning the syntax pattern */
    //SyntaxLearning(SeedDir, DriverDir, SeedAttr);

    /* 2. learning the semantic pattern */
    SemanticLearning(SeedDir, DriverDir, SeedAttr);

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
    DWORD SeedAttr  = SEED_TEXT;
    
    SDWORD Opt = 0;
    while ((Opt = getopt(argc, argv, "s:d:b")) > 0) 
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
            case 'b':
            {
                SeedAttr = SEED_BINARY;
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

    PLEmain (SeedDir, DriverDir, SeedAttr);

    free (SeedDir);
    free (DriverDir);
    return 0;
}