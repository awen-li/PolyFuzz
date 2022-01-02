package JCovPCG;

public class DynTrace {
	
	public native void JvTrace(int TrcKey);
	public native void JvTraceInit (int BBs);
	
	static
	{
        System.loadLibrary("libJvTrace");
    }

}
