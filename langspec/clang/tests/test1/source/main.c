#include <stdio.h>
#include <stdlib.h>

unsigned Getpasswd (unsigned Key);


int main(int argc, char ** argv) 
{
    int Value = atoi (argv[1]);
    unsigned Pwd = 0;

    if (Value >= 4 && Value <= 16)
    {
        Pwd = Getpasswd (Value);
    }
    else
    {
        switch (Value)
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
                Pwd = 8;
            }
        }
    }
    
    return Pwd;
}




