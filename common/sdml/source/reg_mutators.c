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
    if (strcmp (Mu1->StruPattern, Mu2->StruPattern) == 0 &&
        strcmp (Mu1->CharPattern, Mu2->CharPattern) == 0)
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

static inline BOOL IsMutatorExist (BYTE* MuName, BYTE* StruPattern, BYTE* CharPattern)
{
    Mutator Mu = {MuName, StruPattern, CharPattern};

    return IsInList (&g_MuList, (CompData)MutatorCmp, &Mu);
}


VOID RegMutator (BYTE* MuName, BYTE* StruPattern, BYTE* CharPattern)
{   
    if (IsMutatorExist (MuName, StruPattern, CharPattern))
    {
        return;
    }

    DWORD NameLen = strlen ((char*)MuName) + 1;
    DWORD StruPatLen  = strlen ((char*)StruPattern) + 1;
    DWORD CharPatLen  = strlen ((char*)CharPattern) + 1;
    
    Mutator *Mu = (Mutator*) malloc (sizeof (Mutator) + NameLen + StruPatLen + CharPatLen);
    assert (Mu != NULL);

    Mu->MuName  = (BYTE*) (Mu + 1);
    memcpy (Mu->MuName, MuName, NameLen);
    
    Mu->StruPattern = Mu->MuName + NameLen;
    memcpy (Mu->StruPattern, StruPattern, StruPatLen);
    
    Mu->CharPattern = Mu->StruPattern + StruPatLen;
    memcpy (Mu->CharPattern, CharPattern, CharPatLen);

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


VOID GenMutator (SeedPat *SP, List *SpList, BYTE* TestName)
{
    return;
}


VOID DumpOneMutator (Mutator *Mu)
{
    FILE *Fm = fopen (MUTATOR_LIB, "ab");
    assert (Fm != NULL);

    /* pattern */
    DWORD MuLength  = strlen (Mu->MuName);
    DWORD StruLength = strlen (Mu->StruPattern);
    DWORD CharLength = strlen (Mu->CharPattern);
    
    assert (MuLength > 0 && MuLength > 0 && CharLength > 0);

    fwrite (&MuLength,  1, sizeof (DWORD), Fm);
    fwrite (&StruLength, 1, sizeof (DWORD), Fm);
    fwrite (&CharLength, 1, sizeof (DWORD), Fm);

    fwrite (Mu->MuName, 1,  MuLength, Fm);
    fwrite (Mu->StruPattern, 1, StruLength, Fm);   
    fwrite (Mu->CharPattern, 1, CharLength, Fm); 

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

    DWORD MuLength  = 0;
    DWORD StruLength = 0;
    DWORD CharLength = 0;
 
    BYTE  MuName[512];
    BYTE  StruPattern[512];
    BYTE  CharPattern[512];
    
    while (!feof (Fm))
    {
        MuLength = StruLength = CharLength = 0;
        
        fread (&MuLength, 1, sizeof (DWORD), Fm);
        fread (&StruLength, 1, sizeof (DWORD), Fm);
        fread (&CharLength, 1, sizeof (DWORD), Fm);

        if (MuLength == 0)
        {
            break;
        }

        memset (MuName, 0, sizeof (MuName));
        fread (MuName, 1, MuLength, Fm);

        memset (StruPattern, 0, sizeof (StruPattern));
        fread (StruPattern, 1, StruLength, Fm);

        memset (CharPattern, 0, sizeof (CharPattern));
        fread (CharPattern, 1, CharLength, Fm);

        RegMutator (MuName, StruPattern, CharPattern);
    }

    fclose (Fm);
    return;
}


VOID InitMutators ()
{
    LoadMutator ();
    ////////////////////////////////////////////////////////////////

    BYTE CharPat[257];
    memset (CharPat, 1, sizeof (CharPat)); CharPat[256] = 0;
    RegMutator ("DefaultMu", ".*", CharPat);

    printf ("g_MuList.NodeNum = %u \r\n", g_MuList.NodeNum);
    return;
}


VOID DeInitMutators ()
{
    ListDel(&g_MuList, (DelData) free);
    ListDel(&g_SeedList, (DelData) DelSeed);
    return;
}



