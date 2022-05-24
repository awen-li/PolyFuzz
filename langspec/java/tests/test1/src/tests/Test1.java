package tests;
import java.util.Random;

public class Test1 {
	
	private static int Add (int Val1, int Val2)
	{
		switch (Val2)
		{
			case 0:
			case 1:
			case 2:
			{
				switch (Val1)
				{
					case 100: return (Val1 + Val2 + 5);
					case 1000: return (Val1 + Val2 + 30);
					case 10000: return (Val1 + Val2 + 200);
					case 100000: return (Val1 + Val2 + 6000);
					default: return (Val1 + Val2); 
				} 		
			}
			case 3:
			case 6:
			case 9:
			{
				return (Val1 + Val2 + 3);
			}
			default:
			{
				return (Val1 - Val2);
			}
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
