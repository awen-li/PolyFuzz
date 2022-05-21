package CfgSrvDrv;


import java.io.IOException;
import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;

import one.nio.http.HttpServerConfig;
import one.nio.config.*;

/*
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
*/

public class CfgSrvDrv 
{
/*
    private static final String SERVER_CONFIG = "\n" +
            "keepAlive: 120s\n" +
            "maxWorkers: 1000\n" +
            "queueTime: 50MS\n" +
            "\n" +
            "acceptors:\n" +
            " - port: 443\n" +
            "   backlog: 10000\n" +
            "   deferAccept: true\n" +
            "   ssl:\n" +
            "     applicationProtocols: http/1.1\n" +
            "     protocols:            TLSv1+TLSv1.1+TLSv1.2\n" +
            "     certFile:             /etc/ssl/my.crt\n" +
            "     privateKeyFile:       /etc/ssl/my.key\n" +
            "     timeout:              12H\n" +
            " - port: 8443\n" +
            "   ssl: &id1\n" +
            "     applicationProtocols:\n" +
            "      - http/1.1\n" +
            "      - http/2\n" +
            " - port: 9443\n" +
            "   ssl: *id1\n" +
            " - port: 80\n" +
            "   backlog: 10000 \n" +
            "   deferAccept: false\n" +
            "   recvBuf: 32k\n" +
            "   sendBuf: 1M\n" +
            "\n" +
            "virtualHosts:\n" +
            "  admin: admin.example.com\n" +
            "  default: &id2 \n" +
            "   -   example.com\n" +
            "   - www.example.com  \n" +
            "  invalid: *id2\n";


    public static void WritOneCase (String Path, String Content)
    {
        try
        {
            Path p = Paths.get(Path);  
            Files.write(p, Content.getBytes());
            System.out.println (Content);
        }
        catch (IOException e) 
        {
            return;
        }
    }
*/

    public static void main(String[] args)
    {
        String InFile = args [0];

        try
        {
            //WritOneCase ("tests/test1", SERVER_CONFIG);
            
            File FD = new File (InFile);
            InputStream insputStream = new FileInputStream(FD);

            int length = (int)FD.length();
            byte[] bytes = new byte[length];

            insputStream.read(bytes);
            insputStream.close();
                
            HttpServerConfig config = ConfigParser.parse(new String(bytes, "UTF-8"), HttpServerConfig.class);
        }
        catch (IOException e) 
        {
            return;
        }      
    }
}

