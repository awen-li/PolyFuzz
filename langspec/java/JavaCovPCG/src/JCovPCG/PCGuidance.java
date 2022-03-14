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

/*

	public static int pcgCFGAlloct(int EntryId){return 0;};
	public static void pcgCFGDel(int Handle){}
	public static void pcgCFGEdge (int Handle, int Sid, int Eid){}
	public static void pcgBuild (int Handle){}
	public static void pcgInsertIR (int Handle, int Bid, String IR){}
    public static boolean pcgNeedInstrumented (int Handle, int Bid){return false;}
    public static int pcgGetPCGStmtID (int Handle, int Bid) {return 1;}
    public static int[] pcgGetAllSAIStmtIDs(int Handle) {int [] ary = new int [2]; ary[0] = 2; ary[1] = 122; return ary;}
	public static boolean pcgIsDominated (int Handle, int Did, int id){return false;}
	public static boolean pcgIsPostDominated (int Handle, int Did, int id){return false;}
*/
}
