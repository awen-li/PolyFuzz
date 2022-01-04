package JCovPCG;

public class DynTrace {


	public native static void JvTrace(int TrcKey);
	public native static void JvTraceInit (int BBs);
	
	static
	{
        System.loadLibrary("JvTrace");
  }


}
