#include "mutator.h"
#include "list.h"
#include <dirent.h>
#include <sys/stat.h>

static List g_MuList;

VOID RegMutator (BYTE* Pattern, BYTE* MuName)
{
    DWORD PatLen  = strlen ((char*)Pattern) + 1;
    DWORD NameLen = strlen ((char*)MuName) + 1;
    Mutator *Mu = (Mutator*) malloc (sizeof (Mutator) + PatLen + NameLen);
    assert (Mu != NULL);
    
    Mu->Pattern = (BYTE*) (Mu + 1);
    memcpy (Mu->Pattern, Pattern, PatLen);
    
    Mu->MuName  = Mu->Pattern + PatLen;
    memcpy (Mu->MuName, MuName, NameLen);

    Mu->MuEntry = NULL;

    ListInsert(&g_MuList, Mu);
    
    return;
}

static inline BYTE* ReadFile (BYTE* SeedFile, DWORD *SeedLen)
{
    struct stat ST;

    SDWORD S = stat(SeedFile, &ST);
    assert (S != -1);

    FILE *FS = fopen (SeedFile, "rb");
    assert (FS != NULL);

    *SeedLen  = (DWORD)ST.st_size;
    BYTE* Buf = (BYTE*) malloc (ST.st_size);
    assert (Buf != NULL);

    fread (Buf, 1, ST.st_size, FS);
    fclose (FS);
    
    return Buf;
}


static inline BOOL MutatorMatch (Mutator* Mu, BYTE* SeedFile)
{
    return FALSE;
}


Mutator* GetMutator (BYTE* SeedDir)
{
    DIR *Dir;
    struct dirent *SD;
    
    Dir = opendir((const char*)SeedDir);
    if (Dir == NULL)
    {
        return NULL;
    }
    
    while (SD = readdir(Dir))
    {
        if (SD->d_name[0] == '.')
        {
            continue;
        }

        printf ("read -> %s \r\n", SD->d_name);
        ListSearch(&g_MuList, (CompData)MutatorMatch, SD->d_name);
    }
    
    closedir (Dir);
    return NULL;

    return NULL;
}


VOID InitMutators ()
{
    RegMutator ("[.*]", "DefaultMu");
    return;
}


