
#ifndef _BLOCKCFG_H_
#define _BLOCKCFG_H_
#include "GenericGraph.h"
#include "GraphViz.h"

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
public:

    CFGNode(DWORD Id): GenericNode<CFGEdge>(Id) 
    {
        printf ("@@@ new CFG node: %u \r\n", Id);
    }

};


class CFGGraph : public GenericGraph<CFGNode, CFGEdge> 
{

private:
    CFGNode *m_Entry;

public:
    CFGGraph(DWORD EntryId)
    {
        m_Entry = GetCfgNode (EntryId);
        if (m_Entry == NULL)
        {
            m_Entry = new CFGNode (EntryId);
        }
        assert (m_Entry != NULL);
    }
    
    virtual ~CFGGraph() 
    {
    }

    inline CFGNode* GetEntry() const
    {
        return m_Entry;
    }
    
    inline CFGNode* GetCfgNode(DWORD Id) const 
    {
        return GetGNode(Id);
    }

    inline bool InsertEdge (DWORD SId, DWORD EId)
    {
        CFGNode *S = GetCfgNode (SId);
        if (S == NULL)
        {
            S = new CFGNode (SId);
            assert (S != NULL);
            AddNode(SId, S);
        }

        CFGNode *E = GetCfgNode (EId);
        if (E == NULL)
        {
            E = new CFGNode (EId);
            assert (S != NULL);
            AddNode(EId, E);
        }

        CFGEdge *Edge = new CFGEdge (S, E);
        assert (Edge != NULL);

        printf ("### new CFG edge: [%u] ---> [%u] \r\n", S->GetId(), E->GetId());
        return AddEdge (Edge);    
    }
};


class CFGViz: public GraphViz <CFGNode, CFGEdge, CFGGraph>
{

public:
    CFGViz(string GraphName, CFGGraph   * Graph):GraphViz<CFGNode, CFGEdge, CFGGraph>(GraphName, Graph)
    {
    }

    ~CFGViz ()
    {
    }
};


#endif 
