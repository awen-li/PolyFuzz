import java.nio.ByteBuffer;

import one.nio.lz4.LZ4;

public class LZ4Decompres 
{
    static private int Compression(byte[] data) 
    {
        try {
            
            LZ4.decompress(ByteBuffer.wrap(data, 0, data.length), ByteBuffer.allocateDirect(data.length));

        } catch (Exception e) {
            
        }
        
    }
   
    public static void fuzzerTestOneInput(byte[] input)
    {
        Compression (input);
    }
}
