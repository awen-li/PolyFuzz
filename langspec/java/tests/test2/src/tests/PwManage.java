package tests;

public class PwManage {
	
 	public native static String NativePwd (int Key);
 	
 	static
 	{
         System.loadLibrary("JvTest2");
    }

	public static String getPwd(int Key)
	{
		if (Key < 256)
		{
			return NativePwd (Key);	
		}
		else
		{
			return Retrieve (Key);
		}
	}
	
	public static String Retrieve (int Key)
	{
		return "RetrievePwd";
	}

}
