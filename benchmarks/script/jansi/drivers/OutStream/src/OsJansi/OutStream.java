package OsJansi;

import org.fusesource.jansi.AnsiColors;
import org.fusesource.jansi.AnsiMode;
import org.fusesource.jansi.AnsiType;
import org.fusesource.jansi.io.AnsiOutputStream;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;


import java.io.File;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.FileInputStream;

/*
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
*/


public class OutStream 
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
            WritOneCase ("tests/test1", "\u001B[33mbanana_1  |\u001B[0m 19:59:14.353\u001B[0;38m [debug] A message\u001B[0m\n");
            WritOneCase ("tests/test2", "\033]0;ひらがな\007");
            WritOneCase ("tests/test3", "\033]0;un bon café\007");
            WritOneCase ("tests/test4", "ESC[2DESC[2A;un bon café\007");
            WritOneCase ("tests/test5", "@|bold Hello|@");
            WritOneCase ("tests/test6", "\033]0@|324761238ciurhwqhekwc hfdkbosadfasdfasfasdfasdfasdfasdfsadfasdfsf214414';.,.//,,...!@#$%^^&*()_++~@$TERTEYYRTYRTYTTFGD^^&%%ld Hello|@");
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

                String line  = "";
                String Input = "";
                while ((line = BR.readLine()) != null)
                {
                    Input += line;
                }

                final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                final AnsiOutputStream ansiOutput = new AnsiOutputStream(baos, null, AnsiMode.Strip, null, AnsiType.Emulation,
                                                                     AnsiColors.TrueColor, Charset.forName("UTF-8"), null, null, false);
                ansiOutput.write((Input).getBytes());
                //System.out.println(baos.toString());
            }
            catch (Exception e) 
    		{
    			return;
    		}
        }
}

