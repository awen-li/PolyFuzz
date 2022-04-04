package JCovPCG;

public class Debug {
	
	private static boolean flag = false;
	
	public static void DebugPrint (String Info)
	{
		if (flag)
		{
			System.out.println (Info);
		}
	}
	
	public static void SetDebug (boolean DebugSw)
	{
		flag = DebugSw;
	}
}
