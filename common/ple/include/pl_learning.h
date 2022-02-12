/***********************************************************
 * Author: Wen Li
 * Date  : 11/18/2021
 * Describe: pl_learning.h - pattern learning API
 * History:
   <1> 11/18/2021, create
************************************************************/
#ifndef __PL_LEARNING_H__
#define __PL_LEARNING_H__
#include "macro.h"

void SyntaxLearning (BYTE* SeedDir, BYTE* DriverDir, DWORD SeedAttr);
void SemanticLearning (BYTE* SeedDir, BYTE* DriverDir, DWORD SeedAttr);


#endif

