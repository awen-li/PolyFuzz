package JCovPCG;

public class DynTrace {


 	public native static void JvTrace(int BlockID);
	public native static void JvTraceD8(int BlockID, int ValKey, char Value);
	public native static void JvTraceD16(int BlockID, int ValKey, short Value);
	public native static void JvTraceD32(int BlockID, int ValKey, int Value);
	public native static void JvTraceD64(int BlockID, int ValKey, long Value);
	 	
 	public native static void JvTraceInit (int BBs);
 	public native static void JvTraceDeInit (int ExitCode);
 	
 	static
 	{
         System.loadLibrary("JvTrace");
    }

/*	
	public static void JvTrace(int BlockID){}
	public static void JvTraceD8(int BlockID, int ValKey, char Value){}
	public static void JvTraceD16(int BlockID, int ValKey, short Value){}
	public static void JvTraceD32(int BlockID, int ValKey, int Value){}
	public static void JvTraceD64(int BlockID, int ValKey, long Value){}
	
	public static void JvTraceInit (int BBs){}
	public static void JvTraceDeInit (int ExitCode){}
*/
}
