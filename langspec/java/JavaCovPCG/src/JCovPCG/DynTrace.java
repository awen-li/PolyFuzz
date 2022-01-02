package JCovPCG;

public class DynTrace {


//	public native static void JvTrace(int TrcKey);
//	public native static void JvTraceInit (int BBs);
//	
//	static
//	{
//        System.loadLibrary("libJvTrace");
//  }

	public static void JvTrace(int TrcKey)
	{
		System.out.print(TrcKey);
	}
	
	public static void JvTraceInit (int BBs)
	{
		System.out.print(BBs);
	}
}
