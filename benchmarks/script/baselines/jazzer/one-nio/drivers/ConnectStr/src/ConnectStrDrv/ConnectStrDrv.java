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
            byte[] bytes = input;
                
            ConnectionString conn = new ConnectionString(new String(bytes, "UTF-8"));
        }
        catch (IOException e) 
        {
    		return;
        }
    }
}
