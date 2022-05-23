package DcmpZstd;


import java.io.IOException;
import com.github.luben.zstd.Zstd;

public class DeCompress 
{
    public static void fuzzerTestOneInput(byte[] input)
    {
        try
        {
            int length   = input.length;
            byte[] bytes = input;

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

