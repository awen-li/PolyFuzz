package JCovPCG;

public class PCGuidance {


	public native static int pcgCFGAlloct(int EntryId);
	public native static void pcgCFGDel(int Handle);
	public native static void pcgCFGEdge (int Handle, int Sid, int Eid);
	public native static void pcgInsertIR (int Handle, int Bid, String IR);
	public native static void pcgBuild (int Handle);
    public native static boolean pcgNeedInstrumented (int Handle, int Bid);
    public native static int pcgGetPCGStmtID (int Handle, int Bid);
    public native static int[] pcgGetAllSAIStmtIDs(int Handle);
	public native static boolean pcgIsDominated (int Handle, int Did, int id); /* Did dominate id ? */
	public native static boolean pcgIsPostDominated (int Handle, int Did, int id); /* Did post-dominate id ? */

    static
    {
        System.loadLibrary("JvPCGudance");
    }
	
	
}
