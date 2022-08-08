import java.nio.ByteBuffer;

import one.nio.lz4.LZ4;

public class LZ4Drv 
{
    static private int Compression(byte[] data) 
    {
        byte[] compressed = new byte[LZ4.compressBound(data.length)];
        LZ4.compress(data, compressed);
    }
   
    public static void fuzzerTestOneInput(byte[] input)
    {
        Compression (input);
    }
}

