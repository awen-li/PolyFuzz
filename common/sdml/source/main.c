#include "mutator.h"


int main(int argc, char *argv[])
{
    InitMutators ();
    
    SDWORD Opt = 0;
    while ((Opt = getopt(argc, argv, "s:")) > 0) 
    {
        switch (Opt) 
        {
            case 's':
            {
                GetMutator((BYTE*)optarg);
                break;
            }
            default:
            {
                break;
            }

        } 
    }
        
    return 0;
}
