#include "loadbrval.h"
#include "macro.h"
#include <stdio.h>
#include<mxml.h>


namespace pyprob {

using namespace std;

/* brval="addvar:4137755248 " */
void BV_set::DecodeBrVars (BV_file *BVfile, char *BrVars)
{
    char *Val = strtok (BrVars, " ");
    while(Val != NULL) 
    {
        char *Name = strchr (Val, ':');
        if (Name == NULL)
        {
            break;
        }
        *Name = 0;Name++;

        string LineNo (Val);

        char *Key = strchr (Name, ':');
        assert (Key != NULL);
        *Key = 0; Key++;   
        string VarName (Name);
        
        string VarKey (Key);
        
        BVfile->InsertBv((unsigned)stol(LineNo), VarName, (unsigned)stol(VarKey));
        
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
unsigned BV_set::LoadPySummary(string PySummary)
{
    unsigned BlockNum = 0;
    
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
        fprintf(stderr, "No tag branch_variables exist, load a right file?...");
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
            //const char *FuncName = mxmlElementGetAttr(Function, "name");
            //assert (FuncName != NULL);

            //const char *SLine = mxmlElementGetAttr(Function, "sline");
            //assert (SLine != NULL);

            const char *ELine = mxmlElementGetAttr(Function, "eline");
            assert (ELine != NULL);
            
            const char *ValList  = mxmlElementGetAttr(Function, "brval");
            assert (ValList != NULL);

            const char *BBList   = mxmlElementGetAttr(Function, "bbs");
            assert (BBList != NULL);

            /* branch variables */
            DecodeBrVars (BVfile, (char *)ValList);

            /* bbs */
            const char *Bb = strtok ((char *)BBList, " ");
            while(Bb != NULL) 
            {
                BVfile->InsertBb(Bb);
                Bb = strtok(NULL, " ");
            }
            BVfile->InsertBb(ELine); // the end line

            /* next function node */
            Function = mxmlFindElement(Function, tree, "function", NULL, NULL, MXML_DESCEND_FIRST);
            FuncNo++;
        }

        BlockNum += (unsigned)BVfile->m_BBs.size () + 1;

        /* next file node */
        FileNo++;
        File  = mxmlFindElement(File, bvNode, "file", NULL, NULL, MXML_DESCEND);
    }

    mxmlDelete(tree);
    PY_PRINT("LoadPySummary: load %s done, file number:%d , function number:%d, branchs:%u\r\n", 
             PySummary.c_str(), FileNo, FuncNo, m_Branchs);

    return BlockNum;
}


}  // namespace atheris
