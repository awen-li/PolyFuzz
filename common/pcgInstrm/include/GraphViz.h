#ifndef _GRAPHVIZ_H_
#define _GRAPHVIZ_H_
#include <fstream>

using namespace std;

template<class NodeTy,class EdgeTy, class GraphType> class GraphViz 
{
protected:
    FILE  *m_File;
    GraphType *m_Graph;
    string m_GraphName;

protected:
    inline VOID WriteHeader (string GraphName) 
    {
        fprintf(m_File, "digraph \"%s\"{\n", GraphName.c_str());
        fprintf(m_File, "\tlabel=\"%s\";\n", GraphName.c_str()); 

        return;
    }

    virtual inline string GetNodeLabel(NodeTy *Node) 
    {
        string str = "";
        str = "N-" + to_string (Node->GetId ());
        return str;
    }

    
    virtual inline string GetNodeAttributes(NodeTy *Node) 
    {
        string str = "color=black";   
        return str;
    }

    virtual inline string GetEdgeLabel(EdgeTy *Edge) 
    {
        return "";
    }

    virtual inline string GetEdgeAttributes(EdgeTy *Edge) 
    {
        string str = "color=red";
        return str;
    }
 
    inline VOID WriteNodes(NodeTy *Node) 
    {
        /* NodeID [color=grey,label="{NodeID: 0}"]; */
        string str;
        str = "N" + to_string (Node->GetId ()) + " [" + GetNodeAttributes (Node) + 
              ",label=\"" + GetNodeLabel (Node) + "\"];";

        fprintf(m_File, "\t%s\n", str.c_str());
        return;        
    }
 

    inline VOID WriteEdge(EdgeTy *Edge) 
    {
        DWORD SrcId = Edge->GetSrcID ();
        DWORD DstId = Edge->GetDstID ();
        
        /* NodeId -> NodeId[style=solid,color=black, ,label="..."]; */
        string str;

        str = "\tN" + to_string (SrcId) + " -> " + "N" + to_string (DstId) +
              "[" + GetEdgeAttributes (Edge) + ",label=\"\"];";
               
        fprintf(m_File, "%s\n", str.c_str());
        return; 
     
    }

    virtual inline BOOL IsEdgeType (EdgeTy *Edge)
    {
        return TRUE;
    }

public:
    GraphViz(string GraphName, GraphType* Graph) 
    {
        m_GraphName = GraphName;
        
        GraphName = GraphName + ".dot";
        m_File    = fopen (GraphName.c_str(), "w");
        assert (m_File != NULL);

        m_Graph = Graph;
    }

    ~GraphViz()
    {
        fclose (m_File);
    }

    VOID WiteGraph (DWORD EntryId) 
    {
        m_GraphName += to_string (EntryId);
        WriteHeader(m_GraphName);

        for (auto It = m_Graph->begin (), End = m_Graph->end (); It != End; It++)
        {
            NodeTy *Node = It->second;
            WriteNodes (Node);

            for (auto ItEdge = Node->OutEdgeBegin (), ItEnd = Node->OutEdgeEnd (); ItEdge != ItEnd; ItEdge++)
            {
                EdgeTy *Edge = *ItEdge;
                if (!IsEdgeType(Edge))
                {
                    continue;
                }
                
                WriteEdge (Edge);
            }
        }

        fprintf(m_File, "}\n");
    }   
};



#endif 
