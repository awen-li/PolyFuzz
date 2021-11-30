#include "loadbrval.h"
#include "macro.h"
#include <stdio.h>
#include<mxml.h>


namespace pyprob {

using namespace std;

/*
<branch_variables>
  <file name="DemoAdd.py">
    <function brval="addvar" class="DemoAdd" name="_add_"/>
    <function brval="b" class="DemoAdd" name="Add"/>
  </file>
  <file name="Demo.py">
    <function brval="Da Var" class="" name="DemoTr"/>
  </file>
  <file name="setup.py"/>
</branch_variables>

*/
void BV_set::LoadBrVals(string BrValXml)
{
    FILE *fp = fopen(BrValXml.c_str(), "r");
    if (fp == NULL)
    {
        PY_PRINT("LoadBrVals: open %s fail\r\n", BrValXml.c_str());
        return;
    }    
    mxml_node_t* tree = mxmlLoadFile(NULL, fp, MXML_TEXT_CALLBACK);
    fclose(fp);

    /* read branch_variables tag as entry */
    mxml_node_t* bvNode = mxmlFindElement(tree, tree, "branch_variables", NULL, NULL, MXML_DESCEND);
    if (bvNode == NULL)
    {
        PY_PRINT("No tag branch_variables exist, load a right file?...");
        exit (0);
    }

    int FileNo = 0;
    int FuncNo = 0;
    /* read file tag */
    mxml_node_t *File  = mxmlFindElement(bvNode, tree, "file", NULL, NULL, MXML_DESCEND);
    while (File != NULL)
    {
        const char *FileName = mxmlElementGetAttr(File, "name");
        assert (FileName != NULL);
        
        BV_file *BVfile = Insert (FileName);
        assert (BVfile != NULL);
            
        /* read function tag */
        mxml_node_t *Function = mxmlFindElement(File, tree, "function", NULL, NULL, MXML_DESCEND_FIRST);
        while (Function != NULL)
        {
            const char *FuncName = mxmlElementGetAttr(Function, "name");
            assert (FuncName != NULL);
            
            const char *ValList  = mxmlElementGetAttr(Function, "brval");
            assert (ValList != NULL);

            BV_function *BVfunc = BVfile->Insert(FuncName);
            assert (BVfunc != NULL);
            
            const char *Val = strtok ((char *)ValList, " ");
            while(Val != NULL) 
            {
                BVfunc->Insert(Val);   
                Val = strtok(NULL, " ");
            }
            BVfunc->View();

            /* next function node */
            Function = mxmlFindElement(Function, tree, "function", NULL, NULL, MXML_DESCEND_FIRST);
            FuncNo++;
        }

        /* next file node */
        FileNo++;
        File  = mxmlFindElement(File, bvNode, "file", NULL, NULL, MXML_DESCEND);
    }

    mxmlDelete(tree);
    PY_PRINT("LoadBrVals: load %s done, file number:%d , function number:%d\r\n", BrValXml.c_str(), FileNo, FuncNo);


    return;
}


set <string> *BV_set::GetBvSet (string File, string Func)
{
    if (m_BVFileCatch != NULL && m_BVFileCatch->m_FileName == File)
    {
        BV_function *BVFuncCatch = m_BVFileCatch->m_BVFuncCatch;
        if (BVFuncCatch != NULL && BVFuncCatch->m_FuncName == Func)
        {
            return &BVFuncCatch->m_BrVals;
        }
        else
        {
            BVFuncCatch = m_BVFileCatch->Get(Func);
            m_BVFileCatch->m_BVFuncCatch = BVFuncCatch;
            if (BVFuncCatch != NULL)
            {
                return &BVFuncCatch->m_BrVals;
            }
            else
            {
                return NULL;
            }
        }
    }
    else
    {
        m_BVFileCatch = Get (File);
        if (m_BVFileCatch == NULL)
        {
            return NULL;
        }

        BV_function *BVFuncCatch = m_BVFileCatch->Get(Func);
        m_BVFileCatch->m_BVFuncCatch = BVFuncCatch;
        if (BVFuncCatch != NULL)
        {
            return &BVFuncCatch->m_BrVals;
        }
        else
        {
            return NULL;
        }
    }

    return NULL;
}



}  // namespace atheris
