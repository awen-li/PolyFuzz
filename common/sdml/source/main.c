#include "macro.h"


int main(int argc, char *argv[])
{
    SDWORD Opt = 0;
    while ((Opt = getopt(argc, argv, "d:")) > 0) 
    {
        switch (Opt) 
        {
            case 'd':
            {
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
