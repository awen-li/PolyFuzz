package URLEncodDrv;


import java.io.IOException;
import one.nio.util.URLEncoder;


public class URLEncodDrv 
{
    public static void fuzzerTestOneInput(byte[] input)
    {
        try
        {
            byte[] bytes = input;
                
            String Str = URLEncoder.decode(new String(bytes, "UTF-8"));
            URLEncoder.encode(Str);
        }
        catch (Exception e) 
        {
            return;
        }      
    }
}
