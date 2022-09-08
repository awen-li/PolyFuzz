package tests;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

public class Main {

    public static void fuzzerTestOneInput(byte[] input) {
		int Key = 165535;
		
		int value = 0;
        int size  = 0;
        for (byte b : input) {
            value = (value << 8) + (b & 0xFF);

            size++;
            if (size >= 4)
            {
                break;
            }
        }

        Key = value;

		PwManage Pm = new PwManage ();
        String pw = Pm.getPwd(Key);
        //System.out.println ("Run over -> " + pw);
        System.exit(0);
	}

}
