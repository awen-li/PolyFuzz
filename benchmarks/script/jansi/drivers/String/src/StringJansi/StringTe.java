package StringJansi;

import org.fusesource.jansi.Ansi;

import java.io.IOException;
import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;

/*
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
*/

public class StringTe 
{
/*
        public static void WritOneCase (String Path, byte[] Content)
        {
            try
            {
                Path p = Paths.get(Path);  
                Files.write(p, Content);
                System.out.println (Content);
            }
            catch (IOException e) 
    		{
    			return;
    		}
        }

        public static void WritCases ()
        {
            byte[] BytesInfo = new byte [6];
            BytesInfo[0] = 0;
            BytesInfo[1] = 3;
            BytesInfo[2] = 0;
            BytesInfo[3] = 6;
            BytesInfo[4] = 0;
            BytesInfo[5] = 0;
            WritOneCase ("tests/test1", BytesInfo);
        }
*/
        
        public static void main(String[] args)
        {
            String InFile = args [0];

            //WritCases ();
            
            try
            {
                File FD = new File (InFile);
                InputStream insputStream = new FileInputStream(FD);

                int length = (int)FD.length();
                byte[] bytes = new byte[length];

                insputStream.read(bytes);
                insputStream.close();

                int x,y;
                switch (length)
                    {
                        case 0:
                        case 1:return;
                        case 2:
                        case 3:x = bytes[0]; y = bytes[1]; break;
                        default:
                            {
                                x = bytes[0]<<8 | bytes[1];
                                y = bytes[2]<<8 | bytes[3];
                                break;
                            }
                    }

                Ansi ansi = Ansi.ansi().cursor( x, y).reset();
            }
            catch (IOException e) 
    		{
    			return;
    		}
        }
}

