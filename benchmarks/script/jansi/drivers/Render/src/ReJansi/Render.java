package ReJansi;

import static org.fusesource.jansi.Ansi.ansi;
import static org.fusesource.jansi.AnsiRenderer.render;
import static org.fusesource.jansi.AnsiRenderer.renderCodes;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;


import java.io.File;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.FileInputStream;


import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;



public class Render 
{

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
            WritOneCase ("tests/test1", "@|bold foo|@");
            WritOneCase ("tests/test2", "@|bold,red foo|@");
            WritOneCase ("tests/test3", "@|bold,red foo bar baz|@");
            WritOneCase ("tests/test4", "@|bold,red foo bar baz|@ ick @|bold,red foo bar baz|@");
            WritOneCase ("tests/test5", "\033]0@|324761238ciurhwqhekwc hfdkbosadfasdfasfasdfasdfasdfasdfsadfasdfsf214414';.,.//,,...!@#$%^^&*()_++~@$TERTEYYRTYRTYTTFGD^^&%%ld Hello|@");
        }

        
        public static void main(String[] args)
        {
            String InFile = args [0];

            WritCases ();
            
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

                render(Input);
            }
            catch (IOException e) 
    		{
    			return;
    		}
        }
}

