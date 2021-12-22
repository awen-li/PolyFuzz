#include "mutator.h"

static inline VOID  SDML_main (BYTE *SeedDir)
{
    /* 1. search by pattern */
    Mutator *Mu = GetMutator(SeedDir);
    if (Mu != NULL)
    {
        ;
    }

    /* 2. learning the pattern */


    /* 3. update and gen the mutator */


    /* 4. dump */
    DumpMutator ();
    
    return;
}

int main(int argc, char *argv[])
{
    BYTE *SeedDir = NULL;
    
    InitMutators ();
    
    SDWORD Opt = 0;
    while ((Opt = getopt(argc, argv, "s:")) > 0) 
    {
        switch (Opt) 
        {
            case 's':
            {
                SeedDir = (BYTE *)strdup (optarg);
                assert (SeedDir != NULL);
                break;
            }
            default:
            {
                break;
            }

        } 
    }

    if (SeedDir == NULL)
    {
        printf ("the Input seed directory is NULL! \r\n");
        return 0;
    }

    SDML_main (SeedDir);
    
    free (SeedDir); 
    return 0;
}
