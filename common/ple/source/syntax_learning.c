#include <dirent.h>
#include <sys/stat.h>
#include <ctype.h>
#include "pl_struct.h"

static List g_SeedPats;
static List g_SeedList;

static BYTE g_Ascii[256];

/////////////////////////////////////////////////////////////////////////////////////////////////////////

List* GetSeedPatList ()
{
    return &g_SeedPats;
}

List* GetSeedList ()
{
    return &g_SeedList;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////

static inline VOID InitAscii ()
{
    DEBUG ("Init g_Ascii as: ");
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

        #ifdef __DEBUG__
        printf ("%c ", g_Ascii [i]);
        #endif
    }

    DEBUG ("\r\n");
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
    DWORD StartBB = 0;
    int Ret = 0;

    FILE *pf = fopen ("INTERAL_LOC", "r");
    if (pf != NULL)
    {
        Ret = fscanf (pf, "%u", &StartBB);
        assert (Ret != 0);
        fclose (pf);
    }

    if (StartBB != 0)
    {
        StartBB++;
        snprintf (Cmd, sizeof (Cmd), "cd %s; export AFL_START_BB=%u && ./run-fuzzer.sh -P 1", DriverDir, StartBB);
    }
    else
    {
        snprintf (Cmd, sizeof (Cmd), "cd %s; ./run-fuzzer.sh -P 1", DriverDir);
    }

    printf ("CMD: %s \r\n", Cmd);
    Ret = system (Cmd);
    assert (Ret >= 0);
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

    int Ret = fread (&SeedLen, 1, sizeof (DWORD), FS);
    assert (Ret > 0 && SeedLen == S->SeedLen);
    Ret = fread (&CharSize, 1, sizeof (DWORD), FS);
    assert (Ret > 0);

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
        
        int Ret = fread (&CP->CharNum, 1, sizeof (DWORD), FS);
        assert (Ret > 0);
        if (CP->CharNum != 0)
        {
            CP->CharVal = CharValBuf;
            CharValBuf += CP->CharNum;

            Ret = fread (CP->CharVal, 1, CP->CharNum, FS);
            assert (Ret > 0);
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
            if (CP->CharNum == 0) 
            {
                 SP->CharPattern[SeecCtx[Pos]] = CHAR_CRUCIAL;
                 //DEBUG ("\t[%u]CHAR_CRUCIAL: %c (%x): \n", Pos, SeecCtx[Pos], SeecCtx[Pos]);
            }
            else 
            {
                DWORD CharIndex = 0;
                while (CharIndex < CP->CharNum) 
                {
                    BYTE Val = CP->CharVal[CharIndex];
                    if (SP->CharPattern[Val] != CHAR_CRUCIAL)
                    {
                        SP->CharPattern[Val] = CHAR_NORMAL;
                    }
                    
                    CharIndex++;
                }
            }
    
            CP++;
            Pos++;
        }       

        DEBUG ("[%s]character set: %u \r\n", SP->Ss->SName, GetCharPatNum (SP));
        SPHdr = SPHdr->Nxt;
    }

    return;
}


/*
    T = AB
    A = i
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

        for (DWORD Pos = 0; Pos < Ss->SeedSDLen; Pos++)
        {
            BYTE Val = Ss->SeedSD[Pos];
            if (RL == 0 || SP->CharPattern[Val] == CHAR_CRUCIAL)
            {
                Repr[RL++] = Val;
                continue;
            }

            if (Repr[RL-1] == Val)
            {
                Repr[RL-1] = 'B';
                continue;
            }
            else
            {
                BYTE Rb = Repr[RL-1];
                if (Rb == 'w' || Rb == 'd' || Rb == 'B')
                {
                    if (Val == 'w' || Val == 'd' || Val == 'B')
                    {
                        Repr[RL-1] = 'B';
                    }
                    else
                    {
                        Repr[RL++] = Val;
                    }
                }
                else
                {
                    if (Val == 'w' || Val == 'd' || Val == 'B')
                    {
                        Repr[RL++] = 'B';
                    }
                    else
                    {
                        Repr[RL++] = Val;
                    }
                }
            }
        }

        Repr[RL] = 0;
        DEBUG ("Reduce: %s [%u] -> %s [%u] \r\n", Ss->SeedSD, Ss->SeedSDLen, Repr, RL);
        memcpy (Ss->SeedSD, Repr, RL);
        Ss->SeedSDLen = RL;

        RL = 0;
        SPHdr = SPHdr->Nxt;
    }

    return;
}


static inline DWORD N_gramPat (List *SP, List* NgramL, DWORD N_num)
{
    DWORD TotalLen = 0;
    
    BYTE Special[256] = {0};
    Special['{'] = Special['['] = Special['('] = 1;
    Special['}'] = Special[']'] = Special[')'] = 1;
    
    LNode *SPHdr = SP->Header;
    while (SPHdr != NULL)
    {
        SeedPat *SP = (SeedPat *)SPHdr->Data;
        Seed *Ss = SP->Ss;

        if (Ss->SeedSDLen < N_num || Ss->SeedSDLen-2 <= N_num*2)
        {
            SPHdr = SPHdr->Nxt;
            continue;
        }

        TotalLen += Ss->SeedSDLen;
        BYTE* SD = Ss->SeedSD;
        for (DWORD Pos = 0; Pos < Ss->SeedSDLen; Pos++)
        {
            BYTE Val = SD [Pos];
            //DEBUG ("\t %c (%x) -> %u\n", Val, Val, SP->CharPattern[Val]);
            if (Special[Val])
            {
                continue;
            }

            if (Pos+N_num >= Ss->SeedSDLen)
            {
                break;
            }

            N_gram *NG = (N_gram *) malloc (sizeof (N_gram));
            assert (NG != NULL);
            
            NG->N_num = N_num;
            memcpy (NG->Gram, SD+Pos, N_num);
            NG->Gram [N_num] = 0;
            ListInsert(NgramL, NG);
            
            Pos += (N_num-1);
        }
        
        SPHdr = SPHdr->Nxt;
    }

    return TotalLen;
}


static inline BOOL N_gramCmp (N_gram *NG1, N_gram *NG2)
{
    if (NG1->N_num == NG2->N_num &&
        memcmp (NG1->Gram, NG2->Gram, NG1->N_num) == 0)
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

static inline VOID N_gramStat (List* NgramL, List *NgStat, DWORD N_num)
{
    DWORD RepeatNum = 0;
    N_gram *PreNG = NULL; 
    LNode *NGhdr = NgramL->Header;
    while (NGhdr != NULL)
    {
        N_gram *NG = (N_gram *)NGhdr->Data;
        if (PreNG == NULL)
        {
            PreNG = NG;
        }
        else
        {
            if (N_gramCmp (PreNG, NG) == TRUE)
            {
                RepeatNum++;
            }
        }
                
        NGhdr = NGhdr->Nxt;
    }

    if (RepeatNum >= NgramL->NodeNum-1)
    {
        N_gram *NG = (N_gram*) malloc (sizeof (N_gram));
        assert (NG != NULL);
        memcpy (NG, NgramL->Header->Data, sizeof (N_gram));
 
        ListInsert(NgStat, NG);
    }

    return;
}


static inline VOID CalStruPat (List *SPList, List *PbPat)
{ 
    /* reduce the standardlized seed ctx */
    ReduceSeedCtx (SPList);
    
    for (DWORD N_num = 2; N_num < MAX_PAT_LENGTH; N_num++)
    {
        List NgramL;
        NgramL.Header  = NgramL.Tail = NULL;
        NgramL.NodeNum = 0;
        
        DWORD TotalLen = N_gramPat (&g_SeedPats, &NgramL, N_num);
        if (NgramL.NodeNum < SPList->NodeNum)
        {
            ListDel(&NgramL, (DelData)free);
            continue;
        }

        N_gramStat (&NgramL, PbPat, N_num);

        ListDel(&NgramL, (DelData)free);
    }

    LNode *NGhdr = PbPat->Header;
    if (NGhdr != NULL)
    {
        while (NGhdr != NULL)
        {
            N_gram *NG = (N_gram *)NGhdr->Data;
            DEBUG ("@@ POSSIBLE pattern: [N-%u][%s] \r\n", NG->N_num, NG->Gram);

            NGhdr = NGhdr->Nxt;
        }
    }
    else
    {
        /* find no NG pattern, try a last time if reduction is B */
        LNode *SPHdr = SPList->Header;
        DWORD BNum = 0;
        while (SPHdr != NULL)
        {
            SeedPat *SP = (SeedPat *)SPHdr->Data;
            Seed *Ss = SP->Ss;

            if (Ss->SeedSD[0] == 'B')
            {
                BNum++;
            }

            SPHdr = SPHdr->Nxt;
        }

        if (BNum == SPList->NodeNum)
        {
            DEBUG ("@@ POSSIBLE pattern: [N-1][B] \r\n");
            N_gram *NG = (N_gram*) malloc (sizeof (N_gram));
            assert (NG != NULL);
            memset (NG, 0, sizeof (N_gram));
            NG->N_num = 1;
            NG->Gram[0] = 'B';
 
            ListInsert(PbPat, NG);
        }
    }
    
    return;
}


static inline SeedPat* CalRegex (List *SPList)
{
    /* Gen a general regex */
    LNode *SPHdr = SPList->Header;
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
                if (StruPatLen != 0) 
                {
                    /* for simple implemt, we use .* to match all chars */
                    if (Pos == SeedLen-1)
                    {
                        SP->StruPattern[StruPatLen++] = '.';
                        SP->StruPattern[StruPatLen++] = '*';
                    }
                }
                else
                {
                    SP->StruPattern[StruPatLen++] = '^';
                }

                if (Pos == 0 || Pos == SeedLen-1)
                {
                    StruPatLen = MetaCharProc (SP->StruPattern, StruPatLen, SeecCtx[Pos]);
                }
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


VOID DelSeed (Seed *Ss)
{
    free (Ss->SeedSD);
    free (Ss->SeedCtx);
    free (Ss);
}

static VOID DelSeedPat (SeedPat *SP)
{
    ListDel(&SP->UnMatchList, NULL);
    regfree (&SP->StRegex);
    free (SP);

    return;
}

BYTE* ReadFile (BYTE* SeedFile, DWORD *SeedLen, DWORD SeedAttr)
{
    struct stat ST;

    SDWORD S = stat(SeedFile, &ST);
    if (S < 0)
    {
        printf ("[ReadFile] %s stat fail.... \r\n", SeedFile);
        assert (S != -1);
    }

    FILE *FS = NULL;
    if (SeedAttr & SEED_BINARY)
    {
        FS = fopen (SeedFile, "rb");
    }
    else
    {
        FS = fopen (SeedFile, "r");
    }
    assert (FS != NULL);

    *SeedLen  = (DWORD)ST.st_size;

    DWORD BufLen = ST.st_size;
    BufLen = ((BufLen>>2)<<2) + 4;
    BYTE* Buf = (BYTE*) malloc (BufLen);
    assert (Buf != NULL);

    int RdSize = fread (Buf, 1, ST.st_size, FS);
    assert (RdSize != 0);
    Buf[ST.st_size] = 0;
    
    fclose (FS);
    
    return Buf;
}


static inline VOID InitSeedList (BYTE* SeedDir, DWORD SeedAttr)
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
        Ss->SeedCtx = ReadFile (Ss->SName, &Ss->SeedLen, SeedAttr);
        
        Ss->SeedSD    = strdup (Ss->SeedCtx);
        Ss->SeedSDLen = Ss->SeedLen;

        ListInsert(&g_SeedList, Ss);  
    }
    
    closedir (Dir);
    return;
}


VOID BindPatternToSeeds (SeedPat *SP, BYTE* DriverDir)
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
            Temt[Pos] = SP->CharPattern [Ss->SeedCtx[Pos]];
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

        DEBUG("[%s]Seedlen: %u\r\n", Ss->SName, Ss->SeedLen);
        
        SsHdr = SsHdr->Nxt;
    }

    DWORD CharNum = 0;
    Pos = 0;
    while (Pos < sizeof (SP->CharPattern))
    {
        CharNum += (DWORD) (SP->CharPattern[Pos] != 0);
        Pos++;
    }

    snprintf (Path, sizeof (Path), "%s/char.pat", DriverDir);
    FILE *FT = fopen (Path, "wb");
    assert (FT != NULL);

    fwrite (&CharNum, 1, sizeof (CharNum), FT);
    fwrite (SP->CharPattern, 1, sizeof (SP->CharPattern), FT);
    fclose (FT);
    DEBUG("CharNum: %u\r\n", CharNum);

    if (SP->PossPat.NodeNum != 0)
    {
        snprintf (Path, sizeof (Path), "%s/stru.pat", DriverDir);
        FILE *FT = fopen (Path, "wb");
        assert (FT != NULL);

        fwrite (&SP->PossPat.NodeNum, 1, sizeof (DWORD), FT);
        LNode *Pbhdr = SP->PossPat.Header;
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


void SyntaxLearning (BYTE* SeedDir, BYTE* DriverDir, PLOption *PLOP)
{
    InitSeedList (SeedDir, PLOP->SdType);
    
    /* pilot fuzzing */
    RunPilotFuzzing (DriverDir);

    InitAscii ();

    InitSeedPatList (DriverDir);
    assert (g_SeedPats.NodeNum != 0);

    /* calculate char pattern */
    CalCharPat (&g_SeedPats);

    /* calculate regex */
    SeedPat *SP = CalRegex (&g_SeedPats);

    /* calculate structure pattern */
    List *PossPat = &SP->PossPat;
    PossPat->Header  = PossPat->Tail = NULL;
    PossPat->NodeNum = 0;
    CalStruPat (&g_SeedPats, PossPat);


    BindPatternToSeeds (SP, DriverDir);

    ListDel(&g_SeedList, (DelData) DelSeed);
    ListDel(&g_SeedPats, (DelData)DelSeedPat);
    return;
}








