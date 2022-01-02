
#ifndef _BLOCKCFG_H_
#define _BLOCKCFG_H_
#include "GenericGraph.h"


class CFGNode;

class CFGEdge : public GenericEdge<CFGNode> 
{
public:
    CFGEdge(CFGNode* s, CFGNode* d):GenericEdge<CFGNode>(s, d)                       
    {
    }

    virtual ~CFGEdge() 
    {
    }

};


class CFGNode : public GenericNode<CFGEdge> 
{
private:


public:

    CFGNode(DWORD Id): GenericNode<CFGEdge>(Id) 
    {
    }

};


class CFGGraph : public GenericGraph<CFGNode, CFGEdge> 
{

private:
    DWORD m_NodeNum;

public:
    CFGGraph(DWORD NodeNum)
    {
        m_NodeNum = NodeNum;
    }
    
    virtual ~CFGGraph() 
    {
    }
    
    inline CFGNode* GetCgNode(DWORD Id) const 
    {
        return GetGNode(Id);
    }
};



#endif 
