#include "mutator.h"
#include "seedpat.h"
#include <dirent.h>
#include <sys/stat.h>
#include <ctype.h>

static List g_SeedPats;
static BYTE g_Ascii[256];

/////////////////////////////////////////////////////////////////////////////////////////////////////////

List* GetSeedPatList ()
{
    return &g_SeedPats;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////

static inline VOID InitAscii ()
{
    printf ("Init g_Ascii as: ");
    for (DWORD i = 0; i < sizeof (g_Ascii); i++)
    {
        switch (i) 
        {
            case 33 ... 47:
            case 58 ... 64:
            case 91 ... 96:
            case 123 ... 126:
            {
                /* non-digit and non-alpha: save as itself */
                g_Ascii [i] = i;
                break;
            }
            case 48 ... 57:
            {
                /* digit: save as 'd' */
                g_Ascii [i] = 'd';
                break;
            }
            case 65 ... 90:
            case 97 ... 122:
            {
                /* alpha: save as 'w' */
                g_Ascii [i] = 'w';
                break;
            }
            default:
            {
                /* other non-printable: save as 'x' */
                g_Ascii [i] = 'x';
                break;
            }
        }

        printf ("%c ", g_Ascii [i]);
    }

    printf ("\r\n");
    return;
}


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
    SP->MatchNum = 1;

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

static VOID DelSeedPat (SeedPat *SP)
{
    ListDel(&SP->UnMatchList, NULL);
    regfree (&SP->StRegex);
    free (SP);

    return;
}

VOID DeInitSeedPatList ()
{
    ListDel(&g_SeedPats, (DelData)DelSeedPat);
}


static inline SeedPat* PatSelection ()
{
    /* 1. get all patterns' matched and unmatched info, 
          Get the best pattern */

    SeedPat *BestSP = NULL;
    
    LNode *SPHdr = g_SeedPats.Header;
    while (SPHdr != NULL)
    {
        SeedPat *SP  = (SeedPat*)SPHdr->Data;

        LNode *SPHdr2 = g_SeedPats.Header;
        while (SPHdr2 != NULL)
        {
            if (SPHdr2 == SPHdr)
            {
                SPHdr2 = SPHdr2->Nxt;
                continue;
            }

            SeedPat *SP2  = (SeedPat*)SPHdr2->Data;

            INT Ret = regexec(&SP->StRegex, SP2->Ss->SeedCtx, 0, NULL, 0);
            if (Ret == 0) 
            {
                SP->MatchNum++;
                if (BestSP == NULL || BestSP->MatchNum < SP->MatchNum)
                {
                    BestSP = SP;
                }
            }
            else
            {
                ListInsert(&SP->UnMatchList, SP2);
            }

            SPHdr2 = SPHdr2->Nxt;
        }
        
        SPHdr = SPHdr->Nxt;
    }

    printf ("BestSP: %s ----> %s \r\n", BestSP->Ss->SeedCtx, BestSP->StruPattern);
    /* 2. Merge all unmatched pattern to the BestSP */
    List *UnMatchList = &BestSP->UnMatchList;
    if (UnMatchList->NodeNum == 0)
    {
        return BestSP;
    }

    LNode* Hdr = UnMatchList->Header;
    while (Hdr != NULL)
    {
        SeedPat *SP  = (SeedPat*)Hdr->Data;
        strncat (BestSP->StruPattern, "|", sizeof (BestSP->StruPattern));
        strncat (BestSP->StruPattern, SP->StruPattern, sizeof (BestSP->StruPattern));

        Hdr = Hdr->Nxt;
    }

    return BestSP;
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


static inline DWORD MetaCharProc (BYTE* StruPat, DWORD Offset, BYTE Char)
{
    switch (Char)
    {
        case '[':
        case ']':
        case '(':
        case ')':
        {
            StruPat[Offset++] = '\\';
            StruPat[Offset++] = Char;
            break;
        }
        case '{':
        case '}':
        {
            StruPat[Offset++] = '[';
            StruPat[Offset++] = Char;
            StruPat[Offset++] = ']';
            break;            
        }
        default:
        {
            if (!isprint (Char))
            {
                sprintf (StruPat+Offset, "\\x%x", Char);
                Offset += 4;
            }
            else
            {
                StruPat[Offset++] = Char;
            }
            
            break;
        }
    }

    return Offset;
}


static inline VOID StandzSeeds (List *SP)
{
    LNode *SPHdr = SP->Header;
    while (SPHdr != NULL)
    {
        SeedPat *SP = (SeedPat *)SPHdr->Data;
        Seed *Ss = SP->Ss;

        DWORD Pos = 0;
        while (Pos < Ss->SeedLen)
        {
            Ss->SeedSD[Pos] = g_Ascii [Ss->SeedSD[Pos]];
            Pos++;
        }

        DEBUG ("Standz: %s -> %s \r\n", Ss->SeedCtx, Ss->SeedSD);
        SPHdr = SPHdr->Nxt;
    }

    return;
}

static inline VOID CalCharPat (List *SP)
{
    LNode *SPHdr = SP->Header;
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
            //DEBUG ("\t[%u]CharNum: %u ---> %c (%x): \n", Pos, CP->CharNum, SeecCtx[Pos], SeecCtx[Pos]);
            if (CP->CharNum == 0) 
            {
                 SP->CharPattern[SeecCtx[Pos]] = CHAR_CRUCIAL;
            }
            else 
            {
                DWORD CharIndex = 0;
                while (CharIndex < CP->CharNum) 
                {
                    SP->CharPattern[CP->CharVal[CharIndex]] = CHAR_NORMAL;
                    CharIndex++;
                }
            }
    
            CP++;
            Pos++;
        }       
            
        SPHdr = SPHdr->Nxt;
    }

    return;
}


/*
    T = AB
    A = k
    B = d|w|x|i
*/

static inline VOID ReduceSeedCtx (List *SP)
{
    StandzSeeds (SP);

    BYTE Repr[256];
    DWORD RL = 0;
    
    LNode *SPHdr = SP->Header;
    while (SPHdr != NULL)
    {
        SeedPat *SP = (SeedPat *)SPHdr->Data;
        Seed *Ss = SP->Ss;

        for (DWORD Pos = 0; Pos < Ss->SeedLen; Pos++)
        {
            BYTE Val = Ss->SeedSD[Pos];
            if (RL == 0 || SP->CharPattern[Val] == CHAR_CRUCIAL)
            {
                Repr[RL++] = Val;
                continue;
            }

            if (Repr[RL-1] == Val)
            {
                continue;
            }
            else
            {
                Repr[RL++] = Val;
            }
        }

        Repr[RL++] = 0;
        DEBUG ("Reduce: %s -> %s \r\n", Ss->SeedSD, Repr);
        memcpy (Ss->SeedSD, Repr, RL);
        Ss->SeedSDLen = RL-1;

        RL = 0;
        SPHdr = SPHdr->Nxt;
    }

    return;
}


SeedPat* MutatorLearning (BYTE* DriverDir)
{
    /* pilot fuzzing */
    RunPilotFuzzing (DriverDir);

    InitAscii ();

    InitSeedPatList (DriverDir);
    assert (g_SeedPats.NodeNum != 0);

    /* calculate char pattern */
    CalCharPat (&g_SeedPats);

    /* reduce the standardlized seed ctx */
    ReduceSeedCtx (&g_SeedPats);

    /* calculate structure pattern */
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
            DEBUG ("\t[%u]CharNum: %u ---> %c (%x): \n", Pos, CP->CharNum, SeecCtx[Pos], SeecCtx[Pos]);
            if (CP->CharNum == 0) 
            {
                if (StruPatLen != 0) 
                {
                    /* for simple implemt, we use .* to match all chars */
                    SP->StruPattern[StruPatLen++] = '.';
                    SP->StruPattern[StruPatLen++] = '*';
                }
                else
                {
                    SP->StruPattern[StruPatLen++] = '^';
                }

                StruPatLen = MetaCharProc (SP->StruPattern, StruPatLen, SeecCtx[Pos]);
                SP->CharPattern[SeecCtx[Pos]] = CHAR_CRUCIAL;
            }
            else 
            {
                DWORD CharIndex = 0;
                while (CharIndex < CP->CharNum) 
                {
                    //printf ("%c ", CP->CharVal[CharIndex]);
                    SP->CharPattern[CP->CharVal[CharIndex]] = CHAR_NORMAL;
                    CharIndex++;
                }
                //printf ("\n");
            }

            CP++;
            Pos++;
        }

        if (SP->StruPattern[StruPatLen] != '*')
        {
            SP->StruPattern[StruPatLen++] = '$';
        }

        DEBUG ("[%s]STP: %s , CHARP: %u \r\n", SP->Ss->SName, SP->StruPattern, GetCharPatNum (SP));
        
        INT Ret = regcomp(&SP->StRegex, SP->StruPattern, 0);
        if (Ret != 0)
        {
            CHAR ErrBuf[256];
            regerror(Ret, &SP->StRegex, ErrBuf, sizeof (ErrBuf));
            printf ("Regex [%s] compiled fail -> reason[%d]: %s \r\n", SP->StruPattern, Ret, ErrBuf);
            return NULL;
        }
        
        SPHdr = SPHdr->Nxt;
    }

    SeedPat *SpSelect = PatSelection ();
    assert (SpSelect != NULL);

    return SpSelect;
}



