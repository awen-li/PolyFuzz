package ConnectStrDrv;


import java.io.IOException;
import java.nio.ByteBuffer;

import one.nio.net.ConnectionString;


public class ConnectStrDrv 
{
    public static void fuzzerTestOneInput(byte[] input)
    {
        try
        {
            if (input.length == 0) return;
            
            byte[] bytes = input;
                
            ConnectionString conn = new ConnectionString(new String(bytes, "UTF-8"));
        }
        catch (Exception e) 
        {
            return;
        }
    }
}

