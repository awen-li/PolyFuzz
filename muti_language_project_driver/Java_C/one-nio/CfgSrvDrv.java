package CfgSrvDrv;


import java.io.IOException;

import one.nio.http.HttpServerConfig;
import one.nio.config.*;

public class CfgSrvDrv 
{
    public static void fuzzerTestOneInput(byte[] input)
    {
        try
        {
            if (input.length == 0) return;
            byte[] bytes = input;
                
            HttpServerConfig config = ConfigParser.parse(new String(bytes, "UTF-8"), HttpServerConfig.class);
        }
        catch (Exception e) 
        {
            return;
        }      
    }
}

