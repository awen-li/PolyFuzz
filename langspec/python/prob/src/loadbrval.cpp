#include "loadbrval.h"
#include "macro.h"
#include <stdio.h>
#include<mxml.h>


namespace pyprob {

using namespace std;

/* brval="addvar:4137755248 " */
void BV_set::DecodeBrVars (BV_function *BVfunc, char *BrVars)
{
    char *Val = strtok (BrVars, " ");
    while(Val != NULL) 
    {
        char *Spl = strchr (Val, ':');
        if (Spl == NULL)
        {
            break;
        }
        *Spl = 0;
        
        string VarName (Val);
        string VarKey (Spl+1);
        
        BVfunc->InsertBv(VarName, VarKey);
        
        Val = strtok(NULL, " ");
    }

    return;
}


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
void BV_set::LoadPySummary(string PySummary)
{
    FILE *fp = fopen(PySummary.c_str(), "r");
    if (fp == NULL)
    {
        fprintf(stderr, "LoadPySummary: open %s fail\r\n", PySummary.c_str());
        exit (0);
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

            const char *SLine = mxmlElementGetAttr(Function, "sline");
            assert (SLine != NULL);

            const char *ELine = mxmlElementGetAttr(Function, "eline");
            assert (ELine != NULL);
            
            const char *ValList  = mxmlElementGetAttr(Function, "brval");
            assert (ValList != NULL);

            const char *BBList   = mxmlElementGetAttr(Function, "bbs");
            assert (BBList != NULL);

            BV_function *BVfunc = BVfile->Insert(FuncName, FuncNo+1, (unsigned)atoi (SLine), (unsigned)atoi (ELine));
            assert (BVfunc != NULL);

            /* branch variables */
            DecodeBrVars (BVfunc, (char *)ValList);

            /* bbs */
            const char *Bb = strtok ((char *)BBList, " ");
            while(Bb != NULL) 
            {
                BVfunc->InsertBb(Bb);   
                Bb = strtok(NULL, " ");
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
    PY_PRINT("LoadPySummary: load %s done, file number:%d , function number:%d, branchs:%u\r\n", 
             PySummary.c_str(), FileNo, FuncNo, m_Branchs);

    return;
}


int BV_set::GetFIdx (string File, string Func, unsigned LineNo)
{
    PY_PRINT ("GetFIdx -> %s -> %s -> %u \r\n", File.c_str(), Func.c_str(), LineNo);
    if (m_BVFileCatch != NULL && m_BVFileCatch->m_FileName == File)
    {
        BV_function *BVFuncCatch = m_BVFileCatch->m_BVFuncCatch;
        if (BVFuncCatch != NULL && BVFuncCatch->m_FuncName == Func)
        {
            return BVFuncCatch->m_Idx;
        }
        else
        {
            BVFuncCatch = m_BVFileCatch->Get(Func, LineNo);
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

        BV_function *BVFuncCatch = m_BVFileCatch->Get(Func, LineNo);
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
