package DcmpZstd;


import java.io.IOException;
import com.github.luben.zstd.Zstd;

public class DeCompress 
{
    public static void main(String[] args)
    {
        String InFile = args [0];

        byte[] in = new byte[0];
        byte[] compressed = Zstd.compress(in);
        byte[] ob = new byte[100];
        Zstd.decompress(ob, compressed);
    }
}

