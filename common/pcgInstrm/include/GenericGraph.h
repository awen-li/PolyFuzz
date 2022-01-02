
#ifndef _GENERICGRAPH_H_
#define _GENERICGRAPH_H_
#include <set>
#include <map>
#include "MacroDef.h"

using namespace std;

typedef enum
{
    EA_CFG     = 1,
    EA_CFG_DMY = 2,
    EA_DD      = 4,
    EA_CALL    = 8,
    EA_RET     = 16
}EdgeAttr;

template<class NodeTy> class GenericEdge 
{    
private:
    NodeTy* m_SrcNode;
    NodeTy* m_DstNode;

    EdgeAttr m_EdgeAttr;

public:

    GenericEdge(NodeTy* s, NodeTy* d, DWORD Attr = EA_CFG): m_SrcNode(s),m_DstNode(d),m_EdgeAttr((EdgeAttr)Attr)
    {
           
    }

    virtual ~GenericEdge() 
    {
    }

    inline DWORD GetSrcID() const 
    {
        return m_SrcNode->GetId();
    }
    
    inline DWORD GetDstID() const 
    {
        return m_DstNode->GetId();
    }
    
    NodeTy* GetSrcNode() const 
    {
        return m_SrcNode;
    }
    
    NodeTy* GetDstNode() const 
    {
        return m_DstNode;
    }

    inline DWORD GetAttr() const 
    {
        return m_EdgeAttr;
    }

    inline VOID SetAttr(DWORD Attr) 
    {
        m_EdgeAttr = (EdgeAttr)Attr;
    }

    inline bool operator== (const GenericEdge<NodeTy>* rhs) const 
    {
        return (rhs->GetAttr () == this->GetAttr () &&
                rhs->GetSrcID() == this->GetSrcID() &&
                rhs->GetDstID() == this->GetDstID());
    }

    struct EqualGEdge
    {
        bool operator()(const GenericEdge<NodeTy>* lhs, const GenericEdge<NodeTy>* rhs) const 
        {
            if (lhs->GetAttr() != rhs->GetAttr())
            {
                return lhs->GetAttr() < rhs->GetAttr();
            }
            else if (lhs->GetSrcID() != rhs->GetSrcID())
            {
                return lhs->GetSrcID() < rhs->GetSrcID();
            }
            else
            {
                return lhs->GetDstID() < rhs->GetDstID();
            }
        }
    } ;
};


template<class EdgeTy> class GenericNode 
{

public:
    typedef std::set<EdgeTy*, typename EdgeTy::EqualGEdge> T_GEdgeSet;
    typedef typename T_GEdgeSet::iterator iterator;

private:
    DWORD m_Id;

    T_GEdgeSet m_InEdgeSet;  
    T_GEdgeSet m_OutEdgeSet;  

public:
    GenericNode(DWORD Id): m_Id(Id) 
    {
    }

    virtual ~GenericNode() 
    {        
        Release();
    }

    inline VOID Release()
    {
        for (auto In = InEdgeBegin (), End = InEdgeEnd (); In != End; In++)
        {
            RmIncomingEdge(*In);      
        }
        m_InEdgeSet.clear();      
        
        for (auto In = OutEdgeBegin (), End = OutEdgeEnd (); In != End; In++)
        {
            RmOutgoingEdge(*In);      
        }
        m_OutEdgeSet.clear();
    }

    inline DWORD GetId() const
    {
        return m_Id;
    }

    inline VOID SetId(DWORD Id)
    {
        m_Id = Id;
    }

    inline iterator OutEdgeBegin()
    {
        return m_OutEdgeSet.begin();
    }
    
    inline iterator OutEdgeEnd() 
    {
        return m_OutEdgeSet.end();
    }
    
    inline iterator InEdgeBegin() 
    {
        return m_InEdgeSet.begin();
    }
    
    inline iterator InEdgeEnd() 
    {
        return m_InEdgeSet.end();
    }

    inline bool AddIncomingEdge(EdgeTy* InEdge)
    {
        return m_InEdgeSet.insert(InEdge).second;
    }
    
    inline bool AddOutgoingEdge(EdgeTy* OutEdge) 
    {
        return m_OutEdgeSet.insert(OutEdge).second;
    }

    inline VOID RmIncomingEdge(EdgeTy* InEdge) 
    {
        iterator it = m_InEdgeSet.find(InEdge);
        if(it == m_InEdgeSet.end())
        {
            return;
        }

        m_InEdgeSet.erase(InEdge);
        return;
    }
    
    inline VOID RmOutgoingEdge(EdgeTy* OutEdge) 
    {
        iterator it = m_OutEdgeSet.find(OutEdge);
        if(it == m_OutEdgeSet.end())
        {
            return;
        }

        m_OutEdgeSet.erase(OutEdge);
        return;
    }

    inline DWORD GetIncomingEdgeNum ()
    {
        return m_InEdgeSet.size();
    }

    inline DWORD GetOutgoingEdgeNum ()
    {
        return m_OutEdgeSet.size();
    }
};

template<class NodeTy,class EdgeTy> class GenericGraph 
{

public:
    typedef map<DWORD, NodeTy*> T_IDToNodeMap;   
    typedef typename T_IDToNodeMap::iterator node_iterator;

protected:
    DWORD m_NodeNum;
    DWORD m_EdgeNum;
    T_IDToNodeMap m_IDToNodeMap;
    
public:
    
    GenericGraph()
    {
        m_NodeNum = 0;
        m_EdgeNum = 0;
    }

    virtual ~GenericGraph()
    {       
        for (auto I = m_IDToNodeMap.begin(), E = m_IDToNodeMap.end(); I != E; ++I)
        {
            delete I->second;
        }      
    }

    inline node_iterator begin() 
    {
        return m_IDToNodeMap.begin();
    }
    
    inline node_iterator end() 
    {
        return m_IDToNodeMap.end();
    }

    inline VOID AddNode(DWORD id, NodeTy* node) 
    {
        m_IDToNodeMap[id] = node;
        m_NodeNum++;
    }

    inline VOID RmNode(NodeTy* Node) 
    {
        assert(Node->GetIncomingEdgeNum() == 0
               && Node->GetOutgoingEdgeNum() == 0
               && "Node which have edges can't be deleted");
        
        auto it = m_IDToNodeMap.find(Node->GetId());
        assert(it != m_IDToNodeMap.end() && "can not find the node");
        
        m_IDToNodeMap.erase(it);
        m_NodeNum--;

        printf("del node %d \r\n", Node->GetId());
    }

    inline DWORD GetNodeNum() 
    {
        return m_NodeNum;
    }

    inline DWORD GetEdgeNum() 
    {
        return m_EdgeNum;
    }

    inline bool AddEdge(EdgeTy* Edge)
    {
        if (Edge->GetDstNode()->AddIncomingEdge(Edge))
        {
            Edge->GetSrcNode()->AddOutgoingEdge(Edge);

            m_EdgeNum++;

            return true;
        }

        return false;
    }

    inline VOID RmEdge(EdgeTy* Edge)
    {
        Edge->GetDstNode()->RmIncomingEdge(Edge);
        Edge->GetSrcNode()->RmOutgoingEdge(Edge);
            
        m_EdgeNum--;
        delete Edge;
        return;
    }

    inline NodeTy* GetGNode(DWORD id) const 
    {
        auto it = m_IDToNodeMap.find(id);
        if (it != m_IDToNodeMap.end())
        {
            return it->second;
        }
        
        return NULL;
    } 
};

#endif 
