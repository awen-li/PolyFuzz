package jsonden;

import com.google.json.JsonSanitizer;

import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;

public class Denylist 
{
    public static void main(String[] args)
    {
        String InFile = args [0];
            
        try
        {
            File FD = new File (InFile);
            InputStream insputStream = new FileInputStream(FD);

            int length = (int)FD.length();
            byte[] bytes = new byte[length];

            insputStream.read(bytes);
            insputStream.close();

            JsonSanitizer.sanitize(new String (bytes), 10);
        }
        catch (Exception e) 
        {
            return;
        }
    }
}

