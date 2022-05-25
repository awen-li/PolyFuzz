package URLEncodDrv;


import java.io.IOException;
import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;

import one.nio.util.URLEncoder;


public class URLEncodDrv 
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
                
            String Str = URLEncoder.decode(new String(bytes, "UTF-8"));
            URLEncoder.encode(Str);
        }
        catch (Exception e) 
        {
            return;
        }      
    }
}

