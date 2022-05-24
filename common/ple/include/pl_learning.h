/***********************************************************
 * Author: Wen Li
 * Date  : 11/18/2021
 * Describe: pl_learning.h - pattern learning API
 * History:
   <1> 11/18/2021, create
************************************************************/
#ifndef __PL_LEARNING_H__
#define __PL_LEARNING_H__
#include "pl_struct.h"

VOID SetSrvPort (WORD PortNo);

void SyntaxLearning (BYTE* SeedDir, BYTE* DriverDir, PLOption *PLOP);
void SemanticLearning (BYTE* SeedDir, BYTE* DriverDir, PLOption *PLOP);


#endif

