package StringJansi;

import org.fusesource.jansi.Ansi;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.io.File;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.FileInputStream;

/*
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
*/


public class StringTe 
{
/*
        public static void WritOneCase (String Path, String Content)
        {
            try
            {
                Path p = Paths.get(Path);  
                Files.write(p, Content.getBytes());
            }
            catch (IOException e) 
    		{
    			return;
    		}
        }

        public static void WritCases ()
        {
            int x = 3;
            int y = 6;
            int Value = x<<16|y;
            WritOneCase ("tests/test1", Integer.toString (Value));
        }
*/
        
        public static void main(String[] args)
        {
            String InFile = args [0];

            //WritCases ();
            
            try
            {           
                File FD = new File (InFile);
                InputStreamReader RD = new InputStreamReader (new FileInputStream (FD));
                BufferedReader BR    = new BufferedReader (RD);

                String line = BR.readLine();
                byte[] BytesInfo = line.getBytes();

                int x = BytesInfo[1]<<8 | BytesInfo[0];
                int y = BytesInfo[3]<<8 | BytesInfo[2];

                Ansi ansi = Ansi.ansi().cursor( x, y).reset();
                ansi.toString();
            }
            catch (IOException e) 
    		{
    			return;
    		}
        }
}

