package LZ4Drv;


import java.nio.ByteBuffer;

import one.nio.lz4.LZ4;

public class LZ4Drv 
{
    static private int Compression(byte[] data) 
    {
        byte[] compressed = new byte[LZ4.compressBound(data.length)];
        int bytesCompressed = LZ4.compress(data, compressed);
        ByteBuffer out = ByteBuffer.allocateDirect(data.length);
        int bytesUncompressed = LZ4.decompress(ByteBuffer.wrap(compressed, 0, bytesCompressed), out);
        out.flip();
        
        return bytesCompressed;
    }
   
    public static void fuzzerTestOneInput(byte[] input)
    {
        Compression (input);
    }
}

