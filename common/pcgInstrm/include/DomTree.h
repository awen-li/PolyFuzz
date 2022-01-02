
#ifndef _DOMTREE_H_
#define _DOMTREE_H_
#include "GenericGraph.h"

class DomNode;

class DomEdge : public GenericEdge<DomNode> 
{
public:
    DomEdge(DomNode* s, DomNode* d):GenericEdge<DomNode>(s, d)                       
    {
    }

    virtual ~DomEdge() 
    {
    }

};


class DomNode : public GenericNode<DomEdge> 
{
private:


public:

    DomNode(DWORD Id): GenericNode<DomEdge>(Id) 
    {
    }

};


class DomTree : public GenericGraph<DomNode, DomEdge> 
{

private:
    DWORD m_NodeNum;

public:
    DomTree(DWORD NodeNum)
    {
        m_NodeNum = NodeNum;
    }
    
    virtual ~DomTree() 
    {
    }
};


#endif 
