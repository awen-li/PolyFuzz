#include "mutator.h"
#include <dirent.h>
#include <sys/stat.h>

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

Mutator* MutatorLearning (BYTE* DriverDir)
{
    RunPilotFuzzing (DriverDir);

    BYTE *FuzzDir = GetFuzzDir(DriverDir);
    assert (FuzzDir != NULL);
    printf ("DriverDir = %s, Get FuzzDir = %s \r\n", DriverDir, FuzzDir);
    
    
    return NULL;
}


#if 0
patreg_seed *ps = afl->patreg_seed_head;
    while (ps != NULL) {
        u8 pattern[128] = {0};
        u32 pat_len = 0;

        u8* seed_ctx = ps->seed_ctx;
        
        char_pat *cp = ps->char_pat_list;
        u32 pos = 0;
        while (pos < ps->seed_len) {
            /* char num eq 0, means we can not replace it with any other chars */
            if (cp->char_num == 0) {
                if (pat_len != 0) {
                    /* for simple implemt, we use .* to match all chars */
                    pattern[pat_len++] = '.';
                    pattern[pat_len++] = '*';
                }
                pattern[pat_len++] = seed_ctx[pos];
                printf ("%c", seed_ctx[pos]);
            }
            else {
                u32 char_num = 0;
                printf ("[");
                while (char_num < cp->char_num) {
                    printf ("%c ", cp->char_val[char_num]);
                    char_num++;
                }
                printf ("]");
            }
            
            pos++;
            cp++;
        }
        printf ("\npattern recog: %s -> %s \r\n", seed_ctx, pattern);

        ps = ps->next;
    }

#endif

