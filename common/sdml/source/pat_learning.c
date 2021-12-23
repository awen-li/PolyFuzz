#include "mutator.h"
#include "seedpat.h"
#include <dirent.h>
#include <sys/stat.h>

static List g_SeedPats;

static inline BYTE* GetFuzzDir (BYTE* DriverDir)
{
    DIR *Dir;
    struct dirent *SD;
    struct stat ST;

    BYTE WholePath[1024];
    
    Dir = opendir((const char*)DriverDir);
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

        snprintf (WholePath, sizeof(WholePath), "%s/%s", DriverDir, SD->d_name);
        stat(WholePath, &ST);
        if (!S_ISDIR (ST.st_mode))
        {
            continue;
        }

        if (strstr (WholePath, "fuzz") != NULL)
        {
            return strdup (WholePath);
        }
        
        BYTE* FuzzDir = GetFuzzDir (WholePath);
        if (FuzzDir != NULL)
        {
            return FuzzDir;
        }
    }
        
    closedir (Dir);
    return NULL;
}

static inline VOID RunPilotFuzzing (BYTE* DriverDir)
{
    BYTE Cmd[1024];

    snprintf (Cmd, sizeof (Cmd), "cd %s; ./run-fuzzer.sh -P 1", DriverDir);

    printf ("CMD: %s \r\n", Cmd);
    system (Cmd);
    return;
}

static inline BYTE* BaseName (BYTE* Path)
{
    BYTE* Pos = NULL;
    while (*Path != 0)
    {
        if (*Path == '/')
        {
            Pos = Path;
        }
        Path++;
    }

    return Pos;
}


static inline SeedPat* LoadSp (BYTE *Spath, Seed *S)
{
    FILE *FS = fopen (Spath, "rb");
    assert (FS != NULL);
 
//    u32 seed_len;
//    u32 char_size;
//    char_pat []
//         u32 char_num
//         u8[] chars
    DWORD SeedLen  = 0;
    DWORD CharSize = 0;

    fread (&SeedLen, 1, sizeof (DWORD), FS);
    assert (SeedLen == S->SeedLen);
    fread (&CharSize, 1, sizeof (DWORD), FS);

    SeedPat *SP = (SeedPat*) malloc (sizeof (SeedPat) + 
                                     sizeof (CharPat)*SeedLen +
                                     CharSize);
    assert (SP != NULL);
    
    memset (SP->StruPattern, 0, sizeof (SP->StruPattern));
    memset (SP->CharPattern, 0, sizeof (SP->CharPattern));
    SP->Ss = S;
    SP->CharList = (CharPat *)(SP + 1);

    BYTE *CharValBuf = (BYTE*)(SP->CharList + SeedLen);
    DWORD Pos = 0;
    CharPat *CP;
    while (!feof (FS) && Pos < SeedLen)
    {
        CP = SP->CharList + Pos;
        CP->CharNum = 0;
        
        fread (&CP->CharNum, 1, sizeof (DWORD), FS);
        if (CP->CharNum != 0)
        {
            CP->CharVal = CharValBuf;
            CharValBuf += CP->CharNum;

            fread (CP->CharVal, 1, CP->CharNum, FS);
        }

        //printf ("\t==> Pos = %u, CP->CharNum = %u \r\n", Pos, CP->CharNum);
        Pos++;
    }

    fclose (FS);
    return SP;
}


static inline VOID InitSeedPatList (BYTE* DriverDir)
{
    BYTE *FuzzDir = GetFuzzDir(DriverDir);
    assert (FuzzDir != NULL);

    BYTE Spath[512];
    List *SL = GetSeedList();
    LNode *Sh = SL->Header;
    while (Sh != NULL)
    {
        Seed *S = (Seed*)Sh->Data;
    
        BYTE* SeedName = BaseName(S->SName);
        assert (SeedName != NULL);
            
        snprintf (Spath, sizeof (Spath), "%s/in/%s.pat", FuzzDir, SeedName+1);
        printf ("@Mapping: %s ---> %s \n", S->SName, Spath);
    
        SeedPat* SPat = LoadSp (Spath, S);
        assert (SPat != NULL);
    
        ListInsert(&g_SeedPats, SPat);
    
        Sh = Sh->Nxt;
    }

    free (FuzzDir);
    return;
}

static inline VOID DeInitSeedPatList ()
{
    ListDel(&g_SeedPats, (DelData)free);
}


static inline SeedPat* PatSelection ()
{
    return NULL;
}

static inline VOID GenTemplate (SeedPat* SP)
{
    return;
}

static inline DWORD GetCharPatNum (SeedPat *SP)
{
    DWORD Pos = 0;
    DWORD CharPatNum = 0;

    while (Pos < 256)
    {
        if (SP->CharPattern[Pos] != 0)
        {
            CharPatNum++;
        }

        Pos++;
    }

    return CharPatNum;
}


Mutator* MutatorLearning (BYTE* DriverDir)
{
    //RunPilotFuzzing (DriverDir);

    InitSeedPatList (DriverDir);
    assert (g_SeedPats.NodeNum != 0);
    
    LNode *SPHdr = g_SeedPats.Header;
    while (SPHdr != NULL)
    {
        SeedPat *SP  = (SeedPat*)SPHdr->Data;

        DWORD SeedLen = SP->Ss->SeedLen;
        BYTE* SeecCtx = SP->Ss->SeedCtx;

        DWORD Pos = 0;
        DWORD StruPatLen = 0;
        CharPat *CP = SP->CharList;
        while (Pos < SeedLen)
        {
            if (CP->CharNum == 0) 
            {
                if (StruPatLen != 0) 
                {
                    /* for simple implemt, we use .* to match all chars */
                    SP->StruPattern[StruPatLen++] = '.';
                    SP->StruPattern[StruPatLen++] = '*';
                }
                SP->StruPattern[StruPatLen++] = SeecCtx[Pos];
            }
            else 
            {
                DWORD CharIndex = 0;
                while (CharIndex < CP->CharNum) 
                {
                    SP->CharPattern[CP->CharVal[CharIndex]] = 1;
                    CharIndex++;
                }
            }

            CP++;
            Pos++;
        }

        printf ("[%s]STP: %s , CHARP: %u \r\n", SP->Ss->SName, SP->StruPattern, GetCharPatNum (SP));
        SPHdr = SPHdr->Nxt;
    }

    SeedPat *SpSelect = PatSelection ();
    assert (SpSelect != NULL);

    GenTemplate (SpSelect);

    DeInitSeedPatList ();
    return NULL;
}



