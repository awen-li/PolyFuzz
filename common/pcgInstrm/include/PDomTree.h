
#ifndef _GENERICGRAPH_H_
#define _GENERICGRAPH_H_
#include "GenericGraph.h"

class PDomNode;

class PDomEdge : public GenericEdge<PDomNode> 
{
public:
    PDomEdge(PDomNode* s, PDomNode* d):GenericEdge<PDomNode>(s, d)                       
    {
    }

    virtual PDomEdge() 
    {
    }

};


class PDomNode : public GenericNode<PDomEdge> 
{
private:


public:

    PDomNode(DWORD Id): GenericNode<PDomEdge>(Id) 
    {
    }

};


class PDomTree : public GenericGraph<PDomNode, PDomEdge> 
{

private:
    DWORD m_NodeNum;

public:
    PDomTree(DWORD NodeNum)
    {
        m_NodeNum = NodeNum;
    }
    
    virtual ~PDomTree() 
    {
    }
};

#endif 
