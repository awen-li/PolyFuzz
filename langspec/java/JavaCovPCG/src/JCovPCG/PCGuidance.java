package JCovPCG;

public class PCGuidance {
	
//	public native static void pcgCFGAlloct(int EntryId);
//	public native static void pcgCFGEdge (int Sid, int Eid);
//	public native static void pcgBuild ();
//  public native static boolean pcgNeedInstrumented (int Bid);
//	public native static boolean pcgIsDominated (int Did, int id); /* Did dominate id ? */
//	public native static boolean pcgIsPostDominated (int Did, int id); /* Did post-dominate id ? */

//    static
//    {
//        System.loadLibrary("libJvPCGudance.so");
//    }
	
	public static void pcgCFGAlloct(int EntryId)
	{
		System.out.println("pcgCFGAlloct - Entry -> " + EntryId);
	}
	
	public static void pcgCFGEdge (int Sid, int Eid)
	{
		System.out.println("pcgCFGEdge - AddEdge: " + Sid + " -> " + Eid);
	}
	
	public static void pcgBuild ()
	{
		System.out.println("pcgBuild.....");
	}
	
	public static boolean pcgNeedInstrumented (int Bid)
	{
		System.out.println("pcgNeedInstrumented.....");
		return true;
	}

}
