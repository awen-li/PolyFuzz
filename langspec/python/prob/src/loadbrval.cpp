#include "loadbrval.h"
#include <stdio.h>
#include<mxml.h>


namespace pyprob {

using namespace std;

/*
<branch_variables>
  <function brval="b" name="DemoAdd.Add"/>
  <function brval="Var Da" name="DemoTr"/>
</branch_variables>
*/
void LoadBrVals(string BrValXml, unordered_map <string, FBrVal> *BrValMap)
{
    FILE *fp = fopen(BrValXml.c_str(), "r");
    if (fp == NULL)
    {
        cout<<"LoadBrVals: open fail -----> "<<BrValXml<<endl;
        return;
    }    
    mxml_node_t* tree = mxmlLoadFile(NULL, fp, MXML_TEXT_CALLBACK);
    fclose(fp);

    int No = 0;
    mxml_node_t* XmlNode = mxmlFindElement(tree, tree, "branch_variables", NULL, NULL, MXML_DESCEND);
    while (XmlNode != NULL)
    {     
        mxml_node_t *Function  = mxmlFindElement(XmlNode, tree, "function", NULL, NULL, MXML_DESCEND_FIRST);

        const char *FuncName = mxmlElementGetAttr(Function, "name");
        const char *ValList  = mxmlElementGetAttr(Function, "brval");

        cout<<"Get function: "<<FuncName<<" with ValList: "<<ValList<<endl;

        XmlNode = mxmlFindElement(XmlNode, tree, "branch_variables", NULL, NULL, MXML_DESCEND);
        No++;
    }

    mxmlDelete(tree);
    cout<<"LoadBrVals: load done -----> "<<BrValXml<<", function number -> "<<No<<endl;
    
    return;
}


}  // namespace atheris
