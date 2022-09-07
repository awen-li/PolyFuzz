package tests;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

public class Main {

	public static void main(String[] args) {

		int Key = 165535;
		
		if (args.length != 0)
		{
			Path path = Paths.get(args[0]);
			try
			{
				List<String> lines = Files.readAllLines(path);
				Key = Integer.parseInt(lines.get(0));
			}
			catch (Exception e)
			{
				;
			}
		}

		PwManage Pm = new PwManage ();
        String pw = Pm.getPwd(Key);
        //System.out.println ("Run over -> " + pw);
        System.exit(0);
	}

}
