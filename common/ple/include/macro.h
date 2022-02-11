/***********************************************************
 * Author: Wen Li
 * Date  : 9/01/2020
 * Describe: macro.h - common macro definition
 * History:
   <1> 9/01/2020 , create
************************************************************/
#ifndef __MACRO_H__
#define __MACRO_H__ 

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

#define MUTATOR_LIB               ("/usr/bin/libmutators.bin")

#define CHAR_NORMAL               (1)
#define CHAR_CRUCIAL              (2)


#define MAX_PAT_LENGTH            (16)


#define mutex_lock_t              pthread_mutex_t
#define mutex_lock_init(x)        pthread_mutex_init(x, NULL)
#define mutex_lock(x)             pthread_mutex_lock(x);
#define mutex_unlock(x)           pthread_mutex_unlock(x);



#ifdef __DEBUG__
#define DEBUG(format, ...) printf("<debug>" format, ##__VA_ARGS__)
#else
#define DEBUG(format, ...) 
#endif


#endif

