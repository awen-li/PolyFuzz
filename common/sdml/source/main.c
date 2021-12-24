#include "mutator.h"

static inline VOID  SDML_main (BYTE *SeedDir, BYTE * DriverDir, BYTE * TestName)
{
    do
    {
        /* 1. search by pattern */
        Mutator *Mu = GetMutator(SeedDir);
        if (Mu != NULL)
        {
            BindMutatorToSeeds (Mu, SeedDir);
            break;
        }

        /* 2. learning the pattern */
        SeedPat *SP = MutatorLearning(DriverDir);


        /* 3. update and gen the mutator */
        GenMutator (SP, GetSeedPatList(), TestName);

        /* 4. dump */
        DumpMutator ();
    } while (0);

    DeInitMutators ();
    DeInitSeedPatList ();
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
    BYTE *TestName  = NULL;
    
    InitMutators ();
    
    SDWORD Opt = 0;
    while ((Opt = getopt(argc, argv, "s:d:n:")) > 0) 
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
            case 'n':
            {
                TestName = (BYTE *)strdup (optarg);
                assert (TestName != NULL);
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
        printf ("the Input SeedDir = %p, DriverDir = %p! \r\n", SeedDir, DriverDir);
        return 0;
    }

    SDML_main (SeedDir, DriverDir, TestName);

    free (TestName);
    free (SeedDir);
    free (DriverDir);
    return 0;
}
