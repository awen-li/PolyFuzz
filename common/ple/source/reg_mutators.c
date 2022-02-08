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
        if (SD->d_name[0] == '.' || strstr (SD->d_name, ".tmpt") != NULL)
        {
            continue;
        }

        Seed *Ss = (Seed *) malloc (sizeof (Seed));
        assert (Ss != NULL);

        snprintf (Ss->SName, sizeof(Ss->SName), "%s/%s", SeedDir, SD->d_name);
        Ss->SeedCtx = ReadFile (Ss->SName, &Ss->SeedLen);
        
        Ss->SeedSD    = strdup (Ss->SeedCtx);
        Ss->SeedSDLen = Ss->SeedLen;

        ListInsert(&g_SeedList, Ss);  
    }
    
    closedir (Dir);
    return;
}


VOID DelSeed (Seed *Ss)
{
    free (Ss->SeedSD);
    free (Ss->SeedCtx);
    free (Ss);
}

static inline BOOL MutatorCmp (Mutator* Mu1, Mutator* Mu2)
{
    if (strcmp (Mu1->StruPattern, Mu2->StruPattern) == 0 &&
        memcmp (Mu1->CharPattern, Mu2->CharPattern, sizeof (Mu2->CharPattern)) == 0)
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

static inline Mutator* CheckMutator (BYTE* MuName, BYTE* StruPattern, BYTE* CharPattern)
{
    Mutator Mu = {MuName, StruPattern, {0}};
    memcpy (Mu.CharPattern, CharPattern, sizeof (Mu.CharPattern));

    return (Mutator*)ListSearch (&g_MuList, (CompData)MutatorCmp, &Mu);
}


Mutator* RegMutator (BYTE* MuName, BYTE* StruPattern, BYTE* CharPattern, List *PossPat)
{    
    Mutator *Mu;
    
    Mu = CheckMutator (MuName, StruPattern, CharPattern);
    if (Mu != NULL)
    {
        return Mu;
    }

    DWORD NameLen = strlen ((char*)MuName) + 1;
    DWORD StruPatLen  = strlen ((char*)StruPattern) + 1;
    
    Mu = (Mutator*) malloc (sizeof (Mutator) + NameLen + StruPatLen);
    assert (Mu != NULL);
    memset (Mu, 0, sizeof (Mu));

    Mu->MuName  = (BYTE*) (Mu + 1);
    memcpy (Mu->MuName, MuName, NameLen);
    
    Mu->StruPattern = Mu->MuName + NameLen;
    memcpy (Mu->StruPattern, StruPattern, StruPatLen);
    memcpy (Mu->CharPattern, CharPattern, sizeof (Mu->CharPattern));

    if (PossPat != NULL)
    {
        memcpy (&Mu->PossPat, PossPat, sizeof (List));
    }

    DWORD Pos = 0;
    DEBUG ("Crucial bytes: ");
    while (Pos < 256)
    {
        if (Mu->CharPattern[Pos] == CHAR_CRUCIAL)
        {
            #ifdef __DEBUG__
            printf ("%c ", Pos);
            #endif
        }
        Pos++;
    }
    DEBUG ("\n");

    DEBUG ("[RegMutator]%s - %s \r\n", MuName, Mu->StruPattern);
    INT Ret = regcomp(&Mu->StRegex, Mu->StruPattern, 0);
    if (Ret != 0)
    {
        BYTE ErrBuf[256];
        printf ("[%s]Regex [%s] compiled fail -> reason[%d]: %s \r\n", 
                MuName, Mu->StruPattern, Ret, ErrBuf);
        free (Mu);
        return NULL;
    }

    ListInsert(&g_MuList, Mu);
    
    return Mu;
}


static inline BOOL MutatorMatch (Mutator* Mu, Seed* Ss)
{
    INT Ret = regexec(&Mu->StRegex, Ss->SeedCtx, 0, NULL, 0);
    if (Ret == 0)
    {
        return TRUE;
    }

    return FALSE;
}


Mutator* GetMutator (BYTE* SeedDir, BYTE* TestName)
{
    InitSeedList (SeedDir);

    LNode *Hdr = g_SeedList.Header;
    while (Hdr != NULL)
    {   
        Mutator *Mu = ListSearch(&g_MuList, (CompData)MutatorMatch, Hdr->Data);
        if (Mu != NULL)
        {
            if (strcmp (TestName, Mu->MuName) == 0)
            {
                DEBUG ("[GetMutator]%s -> %s \r\n", Mu->MuName, Mu->StruPattern);
                return Mu;
            }
        }

        Hdr = Hdr->Nxt;
    }

    return NULL;
}


VOID BindMutatorToSeeds (Mutator *Mu, BYTE* DriverDir)
{
    DWORD Pos;
    BYTE Path[520];
    
    List *SsList = GetSeedList();
    LNode *SsHdr = SsList->Header;
    while (SsHdr != NULL)
    {
        Seed *Ss = (Seed *)SsHdr->Data;
        
        BYTE *Temt = (BYTE *)malloc (Ss->SeedLen);
        assert (Temt != NULL);
        
        Pos = 0;
        while (Pos < Ss->SeedLen)
        {
            Temt[Pos] = Mu->CharPattern [Ss->SeedCtx[Pos]];
            Pos++;
        }

        snprintf (Path, sizeof (Path), "%s.tmpt", Ss->SName);
        FILE *FT = fopen (Path, "wb");
        assert (FT != NULL);

        fwrite (&Ss->SeedLen, 1, sizeof (Ss->SeedLen), FT);
        fwrite (Temt, 1, Ss->SeedLen, FT);

        free (Temt);
        Temt = NULL;
        fclose (FT);

        DEBUG("[%s]->[%s]Seedlen: %u\r\n", Mu->MuName, Ss->SName, Ss->SeedLen);
        
        SsHdr = SsHdr->Nxt;
    }

    DWORD CharNum = 0;
    Pos = 0;
    while (Pos < sizeof (Mu->CharPattern))
    {
        CharNum += (DWORD) (Mu->CharPattern[Pos] != 0);
        Pos++;
    }

    snprintf (Path, sizeof (Path), "%s/char.pat", DriverDir);
    FILE *FT = fopen (Path, "wb");
    assert (FT != NULL);

    fwrite (&CharNum, 1, sizeof (CharNum), FT);
    fwrite (Mu->CharPattern, 1, sizeof (Mu->CharPattern), FT);
    fclose (FT);
    DEBUG("[%s]CharNum: %u\r\n", Mu->MuName, CharNum);

    if (Mu->PossPat.NodeNum != 0)
    {
        snprintf (Path, sizeof (Path), "%s/stru.pat", DriverDir);
        FILE *FT = fopen (Path, "wb");
        assert (FT != NULL);

        fwrite (&Mu->PossPat.NodeNum, 1, sizeof (DWORD), FT);
        LNode *Pbhdr = Mu->PossPat.Header;
        while (Pbhdr != NULL)
        {
            N_gram *NG = (N_gram *)Pbhdr->Data;
            fwrite (&NG->N_num, 1, sizeof (DWORD), FT);
            fwrite (&NG->Gram, 1, NG->N_num, FT);

            DEBUG("[%s]STRU-PAT: [N-%u]%s\r\n", Path, NG->N_num, NG->Gram);
            Pbhdr = Pbhdr->Nxt;
        }    
        fclose (FT);
        
    }
    
    return;
}


VOID DumpOneMutator (Mutator *Mu)
{
    FILE *Fm = fopen (MUTATOR_LIB, "ab");
    assert (Fm != NULL);

    /* pattern */
    DWORD MuLength  = strlen (Mu->MuName);
    assert (MuLength > 0);
    
    DWORD StruLength = strlen (Mu->StruPattern);
    assert (StruLength > 0);
     
    DWORD CharLength = sizeof (Mu->CharPattern);
    assert (CharLength > 0);

    fwrite (&MuLength,  1, sizeof (DWORD), Fm);
    fwrite (&StruLength, 1, sizeof (DWORD), Fm);
    fwrite (&CharLength, 1, sizeof (DWORD), Fm);

    fwrite (Mu->MuName, 1,  MuLength, Fm);
    fwrite (Mu->StruPattern, 1, StruLength, Fm);   
    fwrite (Mu->CharPattern, 1, CharLength, Fm);

    fwrite (&Mu->PossPat.NodeNum, 1, sizeof (DWORD), Fm);
    LNode *PbHdr = Mu->PossPat.Header;
    while (PbHdr != NULL)
    {
        N_gram *NG = (N_gram *)PbHdr->Data;
        fwrite (NG, 1, sizeof (N_gram), Fm);
        DEBUG ("Dump[%s]NG -> %s \r\n", Mu->MuName, NG->Gram);

        PbHdr = PbHdr->Nxt;
    }

    fclose (Fm);

    DEBUG ("Dump[%s] -> %s \r\n", Mu->MuName, Mu->StruPattern);
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
 
    BYTE  MuName[256];
    BYTE  StruPattern[256];
    BYTE  CharPattern[256];
    
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

        List PossPat;
        memset (&PossPat, 0, sizeof (PossPat));
        DWORD PbNum = 0;
        fread (&PbNum, 1, sizeof (PbNum), Fm);
        for (DWORD i = 0; i < PbNum; i++)
        {
            N_gram *NG = (N_gram *) malloc (sizeof (N_gram));
            assert (NG != NULL);
            fread (NG, 1, sizeof (N_gram), Fm);
            ListInsert(&PossPat, NG);
            DEBUG ("LoadMutator[%s]NG -> %s \r\n", MuName, NG->Gram);
        }

        RegMutator (MuName, StruPattern, CharPattern, &PossPat);
    }

    fclose (Fm);
    return;
}


VOID InitMutators ()
{
    LoadMutator ();
    ////////////////////////////////////////////////////////////////
    BYTE CharPat[256];
    memset (CharPat, 1, sizeof (CharPat));
    CharPat['{'] = CHAR_CRUCIAL;
    CharPat['}'] = CHAR_CRUCIAL;
    RegMutator ("DictMu", "[T].*[T]", CharPat, NULL);

    DEBUG ("[Init]g_MuList.NodeNum = %u \r\n", g_MuList.NodeNum);
    return;
}

VOID DelMu (Mutator *Mu)
{
    ListDel(&Mu->PossPat, free);
    free (Mu);
    return;
}


VOID DeInitMutators ()
{
    ListDel(&g_MuList, (DelData) DelMu);
    ListDel(&g_SeedList, (DelData) DelSeed);
    return;
}



