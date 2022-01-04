#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


char* Getpasswd2 (int Index)
{
    int Val = Index * 4;
    if (Val == 16)
    {
        return "pwd6";
    }
    
    return "default";
}


char* Getpasswd (int Index)
{
    int CallIndex = Index%2;

    if (CallIndex == 0)
    {
        return "pwd0";
    }
    else if (CallIndex == 1)
    {
        return "pwd1";
    }
    else if (CallIndex == 2)
    {
        return "pwd2";
    }
    else if (CallIndex == 3)
    {
        return "pwd3";
    }
    else if (CallIndex == 4)
    {
        return "pwd4";
    }
    else if (CallIndex == 5)
    {
        return "pwd5";
    }
    else
    {
        return Getpasswd2 (CallIndex);
    }
}




