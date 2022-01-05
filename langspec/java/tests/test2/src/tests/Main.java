package tests;

public class Main {

	public static void main(String[] args) {

		int Key = 165535;
		
		if (args.length != 0)
		{
			Key = Integer.parseInt(args[0]);
		}
		
		PwManage Pm = new PwManage ();
        String pw = Pm.getPwd(Key);

        System.out.println ("pw = " + pw);
	}

}
