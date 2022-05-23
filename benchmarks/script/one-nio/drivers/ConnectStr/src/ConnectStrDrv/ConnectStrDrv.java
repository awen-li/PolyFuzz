package ConnectStrDrv;


import java.io.IOException;
import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;
import java.nio.ByteBuffer;

import one.nio.net.ConnectionString;


public class ConnectStrDrv 
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
                
            ConnectionString conn = new ConnectionString(new String(bytes, "UTF-8"));
        }
        catch (Exception e) 
        {
    		return;
        }
    }
}

