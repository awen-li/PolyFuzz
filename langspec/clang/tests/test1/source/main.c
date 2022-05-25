#include <stdio.h>
#include <stdlib.h>

unsigned Getpasswd (unsigned char Key);


int main(int argc, char ** argv) 
{
    if (argc == 1)
    {
        int Index = 0;
        char SEED [32];

        while (Index < 8)
        {
            sprintf (SEED, "seeds/test-%u", Index);
            
            FILE *F = fopen (SEED, "wb");
            unsigned value = (unsigned)random ()%18;
            printf ("value = %u \r\n", value);
            fwrite (&value, 1, sizeof (unsigned), F);
            fclose(F);
            
            Index++;
        }

        return 0;
    }

    unsigned Input = 0;
    FILE *f = fopen (argv[1], "rb");
    fread (&Input, 1, sizeof (Input), f);
    fclose (f);
    
    unsigned char Value = (unsigned char)Input;
    unsigned Pwd = 0;

    if (Value >= 4 && Value <= 16)
    {
        Pwd = Getpasswd (Value);
    }
    else
    {
        /* y = x*x + 5x + 1*/
        unsigned FValue = Value *Value + 5*Value - 100;
        switch (FValue)
        {
            case 0:
            {
                Pwd = 0;
                break;
            }
            case 65535:
            {
                Pwd = 2;
                break;
            }
            case 999999:
            {
                Pwd = 4;
                break;
            }
            default:
            {
                exit (0);
            }
        }
        
    }
    
    return Pwd;
}




