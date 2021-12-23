#include "mutator.h"
#include "seed.h"
#include <dirent.h>
#include <sys/stat.h>

static List g_MuList;
static List g_SeedList;

/////////////////////////////////////////////////////////////////////////////////////////////////////////

List* GetSeedList ()
{
    return &g_SeedList;
}

List* GetMuList ()
{
    return &g_MuList;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////

static inline BYTE* ReadFile (BYTE* SeedFile, DWORD *SeedLen)
{
    struct stat ST;

    SDWORD S = stat(SeedFile, &ST);
    assert (S != -1);

    FILE *FS = fopen (SeedFile, "rb");
    assert (FS != NULL);

    *SeedLen  = (DWORD)ST.st_size;
    BYTE* Buf = (BYTE*) malloc (ST.st_size+1);
    assert (Buf != NULL);

    fread (Buf, 1, ST.st_size, FS);
    Buf[ST.st_size] = 0;
    
    fclose (FS);
    
    return Buf;
}


static inline VOID InitSeedList (BYTE* SeedDir)
{
    DIR *Dir;
    struct dirent *SD;

    Dir = opendir((const char*)SeedDir);
    if (Dir == NULL)
    {
        return;
    }
    
    while (SD = readdir(Dir))
    {
        if (SD->d_name[0] == '.')
        {
            continue;
        }

        Seed *Ss = (Seed *) malloc (sizeof (Seed));
        assert (Ss != NULL);

        snprintf (Ss->SName, sizeof(Ss->SName), "%s/%s", SeedDir, SD->d_name);
        Ss->SeedCtx = ReadFile (Ss->SName, &Ss->SeedLen);

        ListInsert(&g_SeedList, Ss);  
    }
    
    closedir (Dir);
    return;
}


VOID DelSeed (Seed *Ss)
{
    free (Ss->SeedCtx);
    free (Ss);
}

static inline BOOL MutatorCmp (Mutator* Mu1, Mutator* Mu2)
{
    if (strcmp (Mu1->Pattern, Mu2->Pattern) == 0 &&
        strcmp (Mu1->MuName, Mu2->MuName) == 0)
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

static inline BOOL IsMutatorExist (BYTE* Pattern, BYTE* MuName)
{
    Mutator Mu = {Pattern, MuName, NULL};

    return IsInList (&g_MuList, (CompData)MutatorCmp, &Mu);
}


VOID RegMutator (BYTE* Pattern, BYTE* MuName)
{   
    if (IsMutatorExist (Pattern, MuName))
    {
        return;
    }

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


static inline BOOL MutatorMatch (Mutator* Mu, Seed* Ss)
{

    return FALSE;
}


Mutator* GetMutator (BYTE* SeedDir)
{
    InitSeedList (SeedDir);

    LNode *Hdr = g_SeedList.Header;
    while (Hdr != NULL)
    {   
        Mutator *Mu = ListSearch(&g_MuList, (CompData)MutatorMatch, Hdr->Data);
        if (Mu != NULL)
        {
            return Mu;
        }

        Hdr = Hdr->Nxt;
    }

    return NULL;
}


VOID BindMutatorToSeeds (Mutator *Mu, BYTE* SeedDir)
{
    return;
}



VOID DumpOneMutator (Mutator *Mu)
{
    FILE *Fm = fopen (MUTATOR_LIB, "ab");
    assert (Fm != NULL);

    /* pattern */
    DWORD PatLength = strlen (Mu->Pattern);
    DWORD MuLength  = strlen (Mu->MuName);
    assert (PatLength > 0 && MuLength > 0);
    
    fwrite (&PatLength, 1, sizeof (DWORD), Fm);
    fwrite (&MuLength,  1, sizeof (DWORD), Fm);
    
    fwrite (Mu->Pattern, 1, PatLength, Fm);   
    fwrite (Mu->MuName, 1,  MuLength, Fm);

    fclose (Fm);
    
    return;
}

VOID DumpMutator ()
{
    remove (MUTATOR_LIB);
    ListVisit(&g_MuList, (ProcData)DumpOneMutator);
    return;
}



VOID LoadMutator ()
{
    FILE *Fm = fopen (MUTATOR_LIB, "rb");
    if (Fm == NULL)
    {
        return;
    }

    DWORD PatLength = 0;
    DWORD MuLength  = 0;

    BYTE  Pattern[1024];
    BYTE  MuName[1024];
    
    while (!feof (Fm))
    {
        PatLength = MuLength = 0;
        fread (&PatLength, 1, sizeof (DWORD), Fm);
        fread (&MuLength, 1, sizeof (DWORD), Fm);

        if (PatLength == 0 || MuLength == 0)
        {
            break;
        }

        memset (Pattern, 0, sizeof (Pattern));
        fread (Pattern, 1, PatLength, Fm);
        
        memset (MuName, 0, sizeof (MuName));
        fread (MuName, 1, MuLength, Fm);

        RegMutator (Pattern, MuName);
    }

    fclose (Fm);
    return;
}


VOID InitMutators ()
{
    LoadMutator ();
    ////////////////////////////////////////////////////////////////
    
    RegMutator ("[.*]", "DefaultMu");

    printf ("g_MuList.NodeNum = %u \r\n", g_MuList.NodeNum);
    return;
}


VOID DeInitMutators ()
{
    ListDel(&g_MuList, (DelData) free);
    ListDel(&g_SeedList, (DelData) DelSeed);
    return;
}



