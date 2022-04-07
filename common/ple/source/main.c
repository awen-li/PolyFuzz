#include "Queue.h"
#include "pl_learning.h"

static inline VOID  PLEmain (BYTE *SeedDir, BYTE * DriverDir, PLOption *PLOP)
{
    /* 1. learning the syntax pattern */
    //SyntaxLearning(SeedDir, DriverDir, SeedAttr);

    /* 2. learning the semantic pattern */
    SemanticLearning(SeedDir, DriverDir, PLOP);

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
    PLOption PLOP   = {0};

    /* default */
    PLOP.LnThrNum   = 4;
    PLOP.SdPattBits = 1248;
    PLOP.SdType     = SEED_BINARY;
    PLOP.BvDir      = NULL;
    PLOP.TryLength  = LEARN_BLOCK_SIZE * (LEARN_BLOCK_NUM);
    PLOP.SamplePolicy = SP_VARNUM;
    
    SDWORD Opt = 0;
    while ((Opt = getopt(argc, argv, "s:d:bp:t:B:l:qu:")) > 0) 
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
                PLOP.SdType = SEED_BINARY;
                break;
            }
            case 'B':
            {
                PLOP.BvDir = (BYTE *)strdup (optarg);
                assert (DriverDir != NULL);
                FormatPath (PLOP.BvDir);
                break;
            }
            case 'p':
            {
                PLOP.SdPattBits = (DWORD)atoi(optarg);
                break;
            }
            case 't':
            {
                PLOP.LnThrNum   = (DWORD)atoi(optarg);
                break;
            }
            case 'l':
            {
                PLOP.TryLength   = (DWORD)atoi(optarg);
                break;
            }
            case 'q':
            {
                InitQueue(MEMMOD_SHARE);
                ShowQueue(10);
                return 0;                
            }
            case 'u':
            {
                /* udp server port */
                WORD PortNo = (WORD) atoi(optarg);
                SetSrvPort(PortNo);               
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

    PLEmain (SeedDir, DriverDir, &PLOP);

    free (SeedDir);
    free (DriverDir);
    free (PLOP.BvDir);
    return 0;
}
