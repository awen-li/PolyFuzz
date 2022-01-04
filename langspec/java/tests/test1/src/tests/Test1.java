package tests;
import java.util.Random;

public class Test1 {
	
	private static int Add (int Val1, int Val2)
	{
		if (Val2 > 8)
		{
		    return (Val1 + Val2);
		}
		else
		{
			return (Val1 - Val2);
		}
	}

	public static void main(String[] args) {
		Random R = new Random();
		
		int B1 = R.nextInt(10);
		int B2 = R.nextInt(100);
		int Total = 0;
		
		if (B1*2 < B2)
		{
			Total = Add (B1, B2-R.nextInt(20));
		}
		else
		{
			Total = Add (B1, B2);
		}

		System.out.println (Total);
	}

}
