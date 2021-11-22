#include "loadbrval.h"
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
void LoadBrVals(string BrValXml, unordered_map <string, BV_file> *Fname2BVfile)
{
    assert (Fname2BVfile != NULL);
   
    FILE *fp = fopen(BrValXml.c_str(), "r");
    if (fp == NULL)
    {
        cout<<"@@@ LoadBrVals: open fail -----> "<<BrValXml<<endl;
        return;
    }    
    mxml_node_t* tree = mxmlLoadFile(NULL, fp, MXML_TEXT_CALLBACK);
    fclose(fp);

    /* read branch_variables tag as entry */
    mxml_node_t* bvNode = mxmlFindElement(tree, tree, "branch_variables", NULL, NULL, MXML_DESCEND);
    if (bvNode == NULL)
    {
        cout<<"@@@ No tag branch_variables exist, load a right file?..."<<endl;
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
        
        auto It = Fname2BVfile->insert (make_pair(FileName, BV_file (FileName))).first;
        assert (It != NULL);
        BV_file *BVfile = &It->second;
            
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
    cout<<"@@@ LoadBrVals: load done -----> "<<BrValXml<<", file number: "<<FileNo
        <<", function number: "<<FuncNo<<endl;


    return;
}


}  // namespace atheris
