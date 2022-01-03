
#ifndef _BLOCKCFG_H_
#define _BLOCKCFG_H_
#include "GenericGraph.h"
#include "GraphViz.h"
#include <algorithm>

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
        DEBUG ("@@@ new CFG node: %u \r\n", Id);
    }

};


typedef set<CFGNode*> NodeSet;

class CFGGraph : public GenericGraph<CFGNode, CFGEdge> 
{

private:
    CFGNode *m_Entry;
    CFGNode *m_Exit;
    map <CFGNode*, NodeSet*> m_DomSet;
    map <CFGNode*, NodeSet*> m_PostDomSet;

private:

    inline void ViewDom (map <CFGNode*, NodeSet*> *DomSet, string Type, unsigned IterNo)
    {
        #ifdef __DEBUG__
        printf ("@@@ iteration[%u]: \r\n", IterNo);
        for (auto It = DomSet->begin (); It != DomSet->end (); It++)
        {
            CFGNode *N = It->first;
            NodeSet *Doms = It->second;

            printf ("\tNode-%u ---> %s by: ", N->GetId(), Type.c_str());
            for (auto Itd = Doms->begin (); Itd != Doms->end (); Itd++)
            {
                CFGNode *DomNode = *Itd;
                printf ("%u ", DomNode->GetId());
            }
            printf ("\r\n");
        }
        printf ("\r\n");
        #endif
    }

    inline NodeSet* GetDom (map <CFGNode*, NodeSet*> *DomSet, CFGNode* Cn)
    {
        auto It = DomSet->find (Cn);
        if (It != DomSet->end())
        {
            return It->second;
        }
        else
        {
            return NULL;
        }
    }
    
    inline void AddDom (map <CFGNode*, NodeSet*> *DomSet, CFGNode* Cn, CFGNode* Domn)
    {
        auto It = DomSet->find (Cn);
        if (It != DomSet->end())
        {
            NodeSet *Ns = It->second;
            assert (Ns != NULL);
            Ns->insert (Domn);
        }
        else
        {
            NodeSet *Ns = new NodeSet;
            assert (Ns != NULL);
            Ns->insert (Domn);
            (*DomSet) [Cn] = Ns;
        }

        return;
    }

    inline bool UpdateDomByPred (CFGNode *N)
    {
        NodeSet *OrgDomN = GetDom (&m_DomSet, N);
        
        DWORD OrgSize = OrgDomN->size ();
        OrgDomN->clear ();

        NodeSet DomSet;      
        /* iterate all its predecessors */
        for (auto In = N->InEdgeBegin (), End = N->InEdgeEnd (); In != End; In++)
        {
            CFGEdge *InEdge = *In;
            CFGNode *PredN  = InEdge->GetSrcNode ();

            NodeSet*PreDomN = GetDom (&m_DomSet, PredN);
            if (In == N->InEdgeBegin ())
            {
                for (auto It = PreDomN->begin (); It != PreDomN->end (); It++)
                {
                    DomSet.insert (*It);
                }
            }
            else
            {
                NodeSet Dtemp; 
                set_intersection(DomSet.begin(), DomSet.end(),
                                 PreDomN->begin(), PreDomN->end(),
                                 inserter(Dtemp, Dtemp.begin()));
                                 
                DomSet.clear ();
                for (auto It = Dtemp.begin (); It != Dtemp.end (); It++)
                {
                    DomSet.insert (*It);
                }
            }          
        }

        DomSet.insert (N);
        for (auto It = DomSet.begin (); It != DomSet.end (); It++)
        {
            OrgDomN->insert (*It);
        }

        return (bool)(OrgDomN->size () != OrgSize);
    }

    inline bool UpdatePostDomBySucc (CFGNode *N)
    {
        NodeSet *OrgPostDom = GetDom (&m_PostDomSet, N);
        
        DWORD OrgSize = OrgPostDom->size ();
        OrgPostDom->clear ();

        NodeSet PostDomSet;      
        /* iterate all its predecessors */
        for (auto Out = N->OutEdgeBegin (), End = N->OutEdgeEnd (); Out != End; Out++)
        {
            CFGEdge *OutEdge = *Out;
            CFGNode *SuccN = OutEdge->GetDstNode ();

            NodeSet*SuccDomN = GetDom (&m_PostDomSet, SuccN);
            if (Out == N->OutEdgeBegin ())
            {
                for (auto It = SuccDomN->begin (); It != SuccDomN->end (); It++)
                {
                    PostDomSet.insert (*It);
                }
            }
            else
            {
                NodeSet Dtemp; 
                set_intersection(PostDomSet.begin(), PostDomSet.end(),
                                 SuccDomN->begin(), SuccDomN->end(),
                                 inserter(Dtemp, Dtemp.begin()));
                                 
                PostDomSet.clear ();
                for (auto It = Dtemp.begin (); It != Dtemp.end (); It++)
                {
                    PostDomSet.insert (*It);
                }
            }          
        }

        PostDomSet.insert (N);
        for (auto It = PostDomSet.begin (); It != PostDomSet.end (); It++)
        {
            OrgPostDom->insert (*It);
        }

        return (bool)(OrgPostDom->size () != OrgSize);
    }

public:
    CFGGraph(DWORD EntryId)
    {
        m_Entry = GetCfgNode (EntryId);
        if (m_Entry == NULL)
        {
            m_Entry = new CFGNode (EntryId);
            assert (m_Entry != NULL);

            AddNode(EntryId, m_Entry);
        }

        m_Exit = NULL;
    }
    
    virtual ~CFGGraph() 
    {
        for (auto It = m_DomSet.begin (); It != m_DomSet.end (); It++)
        {
            delete It->second;
        }

        for (auto It = m_PostDomSet.begin (); It != m_PostDomSet.end (); It++)
        {
            delete It->second;
        }
    }

    inline CFGNode* GetEntry()
    {
        return m_Entry;
    }

    inline CFGNode* GetExit()
    {
        if (m_Exit != NULL)
        {
            return m_Exit;
        }

        for (auto It = begin(); It != end (); It++)
        {
            CFGNode *N = It->second;
            if (N->GetOutgoingEdgeNum() == 0)
            {
                m_Exit = N;
                break;
            }
        }

        return m_Exit;
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

        DEBUG ("### new CFG edge: [%u] ---> [%u] \r\n", S->GetId(), E->GetId());
        return AddEdge (Edge);    
    }


    inline void ComputeDom ()
    { 
        /* entry node */
        AddDom (&m_DomSet, m_Entry, m_Entry);

        /* init other node (-entry) */
        for (auto It = begin(); It != end (); It++)
        {
            CFGNode *N = It->second;
            if (N == m_Entry)
            {
                continue;
            }

            for (auto It2 = begin(); It2 != end (); It2++)
            {
                CFGNode *Domn = It2->second;
                AddDom (&m_DomSet, N, Domn);
            }         
        }

        /* compute dominace */
        unsigned IterNo = 0;
        bool Changed = true;
        while (Changed)
        {
            Changed = false;
            for (auto It = begin(); It != end (); It++)
            {
                CFGNode *N = It->second;
                if (N == m_Entry)
                {
                    continue;
                }

                Changed |= UpdateDomByPred (N);       
            }

            ViewDom (&m_DomSet, "Dominated", IterNo);
            IterNo++;
        }
    }

    inline void ComputePostDom ()
    {
        CFGNode *m_Exit = GetExit();
        assert (m_Exit != NULL);
        
        /* entry node */
        AddDom (&m_PostDomSet, m_Exit, m_Exit);

        /* init other node (-entry) */
        for (auto It = begin(); It != end (); It++)
        {
            CFGNode *N = It->second;
            if (N == m_Exit)
            {
                continue;
            }

            for (auto It2 = begin(); It2 != end (); It2++)
            {
                CFGNode *Domn = It2->second;
                AddDom (&m_PostDomSet, N, Domn);
            }         
        }

        /* compute dominace */
        unsigned IterNo = 0;
        bool Changed = true;
        while (Changed)
        {
            Changed = false;
            for (auto It = begin(); It != end (); It++)
            {
                CFGNode *N = It->second;
                if (N == m_Exit)
                {
                    continue;
                }

                Changed |= UpdatePostDomBySucc (N);       
            }

            ViewDom (&m_PostDomSet, "Post-Dominated", IterNo);
            IterNo++;
        }
    }

    inline NodeSet* GetDomSet (DWORD NodeId)
    {
        CFGNode *Cn = GetGNode(NodeId);
        assert (Cn != NULL);

        NodeSet* Ns = GetDom (&m_DomSet, Cn);
        return Ns;
    }

    inline NodeSet* GetPostDomSet (DWORD NodeId)
    {
        CFGNode *Cn = GetGNode(NodeId);
        assert (Cn != NULL);

        NodeSet* Ns = GetDom (&m_PostDomSet, Cn);
        return Ns;
    }

    inline bool IsFullDominator (DWORD NodeId)
    {
        CFGNode *Cn = GetGNode(NodeId);
        assert (Cn != NULL);

        for (auto Out = Cn->OutEdgeBegin (), End = Cn->OutEdgeEnd (); Out != End; Out++)
        {
            CFGEdge *OutEdge = *Out;
            CFGNode *SuccN = OutEdge->GetDstNode ();

            NodeSet* Ns = GetDom (&m_PostDomSet, SuccN);
            if (Ns->find (Cn) == Ns->end ())
            {
                return false;
            }
        }

        
        return true;
    }

    inline bool IsFullPostDominator (DWORD NodeId)
    {
        CFGNode *Cn = GetGNode(NodeId);
        assert (Cn != NULL);

        for (auto In = Cn->InEdgeBegin (), End = Cn->InEdgeEnd (); In != End; In++)
        {
            CFGEdge *InEdge = *In;
            CFGNode *PredN = InEdge->GetSrcNode ();

            NodeSet* Ns = GetDom (&m_PostDomSet, PredN);
            if (Ns->find (Cn) == Ns->end ())
            {
                return false;
            }
        }
        return true;
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
