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
    mxml_node_t* bvNode = mxmlFindElement(tree, tree, "py_summary", NULL, NULL, MXML_DESCEND);
    if (bvNode == NULL)
    {
        PY_PRINT("No tag branch_variables exist, load a right file?...");
        exit (0);
    }
    const char *Branchs = mxmlElementGetAttr(bvNode, "branchs");
    assert (Branchs != NULL);
    m_Branchs = (unsigned) atoi (Branchs);

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

            const char *BBList   = mxmlElementGetAttr(Function, "bbs");
            assert (BBList != NULL);

            BV_function *BVfunc = BVfile->Insert(FuncName, FuncNo+1);
            assert (BVfunc != NULL);

            /* branch variables */
            const char *Val = strtok ((char *)ValList, " ");
            while(Val != NULL) 
            {
                BVfunc->InsertBv(Val);   
                Val = strtok(NULL, " ");
            }

            /* bbs */
            const char *Bb = strtok ((char *)BBList, " ");
            while(Bb != NULL) 
            {
                BVfunc->InsertBb(Bb);   
                Bb = strtok(NULL, " ");
            }
            
            //BVfunc->View();

            /* next function node */
            Function = mxmlFindElement(Function, tree, "function", NULL, NULL, MXML_DESCEND_FIRST);
            FuncNo++;
        }

        /* next file node */
        FileNo++;
        File  = mxmlFindElement(File, bvNode, "file", NULL, NULL, MXML_DESCEND);
    }

    mxmlDelete(tree);
    PY_PRINT("LoadBrVals: load %s done, file number:%d , function number:%d, branchs:%u\r\n", 
             BrValXml.c_str(), FileNo, FuncNo, m_Branchs);

    return;
}


int BV_set::GetFIdx (string File, string Func)
{
    if (m_BVFileCatch != NULL && m_BVFileCatch->m_FileName == File)
    {
        BV_function *BVFuncCatch = m_BVFileCatch->m_BVFuncCatch;
        if (BVFuncCatch != NULL && BVFuncCatch->m_FuncName == Func)
        {
            return BVFuncCatch->m_Idx;
        }
        else
        {
            BVFuncCatch = m_BVFileCatch->Get(Func);
            m_BVFileCatch->m_BVFuncCatch = BVFuncCatch;
            if (BVFuncCatch != NULL)
            {
                return BVFuncCatch->m_Idx;
            }
            else
            {
                return 0;
            }
        }
    }
    else
    {
        m_BVFileCatch = Get (File);
        if (m_BVFileCatch == NULL)
        {
            return 0;
        }

        BV_function *BVFuncCatch = m_BVFileCatch->Get(Func);
        m_BVFileCatch->m_BVFuncCatch = BVFuncCatch;
        if (BVFuncCatch != NULL)
        {
            return BVFuncCatch->m_Idx;
        }
        else
        {
            return 0;
        }
    }

    return 0;
}



}  // namespace atheris
