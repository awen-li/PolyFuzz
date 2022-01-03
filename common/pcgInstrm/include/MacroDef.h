/***********************************************************
 * Author: Wen Li
 * Date  : 9/01/2020
 * Describe: MacroDef.h - Macro definition 
 * History:
   <1> 9/01/2020 , create
************************************************************/

#ifndef _MACRODEF_H_
#define _MACRODEF_H_ 
#ifdef __cplusplus
extern "C"{
#endif 

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>

typedef unsigned char    BYTE;
typedef signed char      CHAR;
typedef unsigned int     DWORD;
typedef signed int       INT;
typedef unsigned short   WORD;
typedef unsigned long    ULONG;
typedef signed int       SDWORD;
typedef signed short     SWORD;
typedef void             VOID;
typedef void             PRAVOID;
typedef unsigned         BOOL;


#define R_SUCCESS                 (0)
#define R_FAIL                    (1)

#define TRUE                      (1)
#define FALSE                     (0)

#define SHARE_KEY                 (0xC3B3C5D0)

#define ALIGN_8(x)                (((x)%8)?(((x)&~7) + 8):(x))

#define INLINE                    inline


#ifdef __DEBUG__
#define DEBUG(format, ...) printf("<PCG>" format, ##__VA_ARGS__)
#else
#define DEBUG(format, ...) 
#endif


#ifdef __cplusplus
}
#endif

#endif

