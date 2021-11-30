#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


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
    else
    {
        return "pwd2";
    }
}




