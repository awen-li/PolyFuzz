
#ifndef _BLOCKCFG_H_
#define _BLOCKCFG_H_
#include "GenericGraph.h"
#include "GraphViz.h"
#include <algorithm>
#include <vector>

using namespace std;
class CFGNode;

enum
{
    V_TYPE_OTHER=0,
    V_TYPE_INT=1,
    V_TYPE_NONE=255,
};

enum
{
    STMT_OTHER=0,
    STMT_CMP=1,
    STMT_SWITCH=2,
};


struct ValueIR
{
    DWORD m_Type;
    string m_Name;

    ValueIR ()
    {
        m_Type = V_TYPE_NONE;
        m_Name = "";
    }
};

struct StmtIR
{
    DWORD m_StId;
    DWORD m_CMP;
    ValueIR m_Def;
    vector<ValueIR> m_Uses;

    string m_IRExpr;
    
    StmtIR (string IRExpr)
    {
        m_StId   = -1;
        m_CMP    = 0;
        m_IRExpr = IRExpr;

        Decode(IRExpr);
        //ShowStmt ();
    }

    /* SA-IR
     * Type: i: integer, o: other 
     *  compare statement: ID:CMP|SWITCH:DEF#T:USE1#T:USE2#T:...:USEN#T
     *  other statement: 
     * */

    inline void DecodeValue (string Value, ValueIR &VI)
    {
        DEBUG ("[DecodeValue]Value = %s \r\n", Value.c_str ());
        size_t pos = Value.find("#");
        assert (pos != Value.npos && pos > 0);

        VI.m_Name = Value.substr(0, pos);  
        string Type = Value.substr(pos+1, Value.size());   
        if (Type == "i")
        {
            VI.m_Type = V_TYPE_INT;
        }
        else if (Type == "o")
        {
            VI.m_Type = V_TYPE_OTHER;
        }
        else
        {
            assert (0);
        }

        return;
    }
    
    inline void Decode (string IRExpr)
    {
        DEBUG ("[Decode]IRExpr = %s \r\n", IRExpr.c_str ());
        
        DWORD IDX = 0;
        size_t pos = IRExpr.find(":");
        while(pos != IRExpr.npos)
        {
            string Temp = IRExpr.substr(0, pos);
            if (Temp != "")
            {                
                switch (IDX)
                {
                    case 0:
                    {
                        m_StId = std::stoi(Temp);
                        break;
                    }
                    case 1:
                    {
                        if (Temp == "CMP")
                        {
                            m_CMP = STMT_CMP;
                        }
                        else if (Temp == "SWITCH")
                        {
                            m_CMP = STMT_SWITCH;
                        }
                        else
                        {
                            m_CMP = STMT_OTHER;
                        }
                        break;
                    }
                    case 2:
                    {
                        DecodeValue (Temp, m_Def);
                        break;
                    }
                    default:
                    {
                        ValueIR Use;
                        DecodeValue (Temp, Use);
                        m_Uses.push_back (Use);
                        break;
                    }
                }
            }

            IDX++;
            IRExpr = IRExpr.substr(pos+1, IRExpr.size());
            pos = IRExpr.find(":");
        }    
    }

    inline void ShowStmt ()
    {
        printf ("\t\t[STMT]%s  --->Decode: [%u]", m_IRExpr.c_str (), m_StId);
        printf ("CMP:%u, ", m_CMP);
        printf ("Def: %s:%u, Uses: ", m_Def.m_Name.c_str(), m_Def.m_Type);
        if (m_Uses.size ())
        {
            for (DWORD ix = 0; ix < m_Uses.size (); ix++)
            {
                printf ("%s:%u  ", m_Uses[ix].m_Name.c_str(), m_Uses[ix].m_Type);
            }
        }
        printf ("\r\n");
    }
};

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
    typedef typename vector<StmtIR>::iterator st_iterator;
    
public:
    vector<StmtIR> m_Stmts;
    vector<StmtIR*> m_BrDefStmts;
    set<StmtIR*> m_InstrmedSet;

    CFGNode(DWORD Id): GenericNode<CFGEdge>(Id) 
    {
        DEBUG ("@@@ new CFG node: %u \r\n", Id);
    }

    inline void AddStmtIR (const char* IRExpr)
    {
        StmtIR SIR (IRExpr); 
        m_Stmts.push_back (SIR);
        return;
    }

    inline st_iterator begin ()
    {
        return m_Stmts.begin ();
    }

    inline st_iterator end ()
    {
        return m_Stmts.end ();
    }

    inline unsigned GetPCGStmtID ()
    {
        if (m_BrDefStmts.size () == 0)
        {
            return 0;
        }

        StmtIR *SIR = m_BrDefStmts[0];
        m_InstrmedSet.insert (SIR);

        return SIR->m_StId;
    }

    inline unsigned IsInstrumented (StmtIR *SIR)
    {
        auto It = m_InstrmedSet.find (SIR);
        if (It == m_InstrmedSet.end ())
        {
            return 0;
        }
        else
        {
            return 1;
        }
    }
};


typedef set<CFGNode*> NodeSet;

class CFGGraph : public GenericGraph<CFGNode, CFGEdge> 
{
public:
    typedef set<string> T_ValueSet;


private:
    CFGNode *m_Entry;
    CFGNode *m_Exit;
    map <CFGNode*, NodeSet*> m_DomSet;
    map <CFGNode*, NodeSet*> m_PostDomSet;

    map<StmtIR*, StmtIR*> BrDefStmt2PosStmt;

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

    
    inline void ComputePostDom ()
    {  
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

    inline VOID UpdateExit()
    {
        set <CFGNode*> ExitSet;
        
        for (auto It = begin(), End = end (); It != End; It++)
        {
            CFGNode *N = It->second;
            if (N->GetOutgoingEdgeNum() == 0)
            {
                ExitSet.insert (N);
            }
        }

        DWORD ExitNum = ExitSet.size ();
        if (ExitNum == 0)
        {
            /* loop existed */
            for (auto It = begin(), End = end (); It != End; It++)
            {
                CFGNode *N = It->second;
                if (N->GetIncomingEdgeNum() >= 2)
                {
                    ExitSet.insert (N);
                }
            }

            ExitNum = ExitSet.size ();
            assert (ExitNum > 0);
        }

        if (ExitNum == 1)
        {
            m_Exit = *(ExitSet.begin ());
            return;
        }

        DEBUG ("@@@ Total %u exits in CFG, construct dumy exit node....\r\n", ExitNum);
        DWORD DumyExit = 16777215; /* large enough */
        for (auto It = ExitSet.begin (), End = ExitSet.end (); It != End; It++)
        {
            CFGNode *S = *It;
            InsertEdge (S->GetId(), DumyExit);
        }
        
        m_Exit = GetCfgNode (DumyExit);
        assert (m_Exit != NULL);
        DEBUG ("@@@ Set exit node as %u ....\r\n", DumyExit);

        return;
    }

    inline CFGNode* GetCfgNode(DWORD Id) const 
    {
        return GetGNode(Id);
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

    inline VOID BuildCFG ()
    {
        UpdateExit();

        DEBUG ("@@@ Start ComputeDom...\r\n");
        ComputeDom ();

        DEBUG ("@@@ Start ComputePostDom...\r\n");
        ComputePostDom ();

        CollectBrDefUse ();

        return;
    }

    inline CFGNode* GetEntry()
    {
        return m_Entry;
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

    inline void CollectBrDefUse () 
    {
        T_ValueSet BrValueSet;

        /* 1. get ALL branch variables in branch/switch instructions*/
        for (auto It = begin (), End = end (); It != End; It++) 
        {
            CFGNode *CN = It->second;
            for (auto SIt = CN->begin (), SEnd = CN->end(); SIt != SEnd; SIt++)
            {
                StmtIR *SIR = &(*SIt);
                if (SIR->m_CMP == STMT_CMP)
                {
                    BrValueSet.insert (SIR->m_Uses[0].m_Name);
                    BrValueSet.insert (SIR->m_Uses[1].m_Name);
                }
                else if (SIR->m_CMP == STMT_SWITCH)
                {
                    BrValueSet.insert (SIR->m_Uses[0].m_Name);
                }
            }
        }

        /* 2. get DEF of branch variables */
        for (auto It = begin (), End = end (); It != End; It++) 
        {
            CFGNode *CN = It->second;
            for (auto SIt = CN->begin (), SEnd = CN->end(); SIt != SEnd; SIt++)
            {
                StmtIR *SIR = &(*SIt);                
                if (SIR->m_Def.m_Type == V_TYPE_NONE ||
                    SIR->m_Def.m_Type == V_TYPE_OTHER)
                {
                    continue;
                }

                auto DefIt = BrValueSet.find (SIR->m_Def.m_Name);
                if (DefIt == BrValueSet.end ())
                {
                    continue;
                }

                CN->m_BrDefStmts.push_back (SIR);

                printf ("@@@ Get BrDef: ");
                SIR->ShowStmt();
            }
        }

        return;
    }


    inline unsigned GetAllSAIStmts (unsigned** SAIStmtIDs)
    {
        vector<unsigned> VecSAIStmt;
        for (auto It = begin (), End = end (); It != End; It++) 
        {
            CFGNode *CN = It->second;
            for (auto SIt = CN->m_BrDefStmts.begin (), SEnd = CN->m_BrDefStmts.end (); SIt != SEnd; SIt++)
            {
                StmtIR *SIR = *SIt;
                if (CN->IsInstrumented(SIR))
                {
                    continue;
                }

                VecSAIStmt.push_back (SIR->m_StId);
            }
        }

        unsigned StmtNum = (unsigned)VecSAIStmt.size ();
        unsigned *StmtIDs = (unsigned *)malloc (sizeof (unsigned) * StmtNum);
        assert (StmtIDs != NULL);

        for (unsigned ix = 0; ix < StmtNum; ix++)
        {
            StmtIDs [ix] = VecSAIStmt[ix];
        }
        
        *SAIStmtIDs = StmtIDs;
        return StmtNum;
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
