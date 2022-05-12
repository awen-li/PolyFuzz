package DcmpZstd;


import java.io.IOException;
import java.io.IOException;
import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;

import com.github.luben.zstd.Zstd;

public class DeCompress 
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

            byte[] compressed = Zstd.compress(bytes);
            byte[] ob = new byte[length];
            Zstd.decompress(ob, compressed);
        }
        catch (Exception e) 
        {
            return;
        }      
    }
}

