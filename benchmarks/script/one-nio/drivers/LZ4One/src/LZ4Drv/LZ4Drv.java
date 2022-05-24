package LZ4Drv;


import java.io.IOException;
import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;
import java.nio.ByteBuffer;

import one.nio.lz4.LZ4;

/*
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
*/


public class LZ4Drv 
{
/*
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
    static private int Compression(byte[] data) 
    {
        byte[] compressed = new byte[LZ4.compressBound(data.length)];
        int bytesCompressed = LZ4.compress(data, compressed);
        ByteBuffer out = ByteBuffer.allocateDirect(data.length);
        int bytesUncompressed = LZ4.decompress(ByteBuffer.wrap(compressed, 0, bytesCompressed), out);
        out.flip();
        
        return bytesCompressed;
    }
   
    public static void main(String[] args)
    {
        String InFile = args [0];

        //WritOneCase ("tests/test1", TEST_CONFIG);
        
        try
        {
            File FD = new File (InFile);
            InputStream insputStream = new FileInputStream(FD);

            int length = (int)FD.length();
            byte[] bytes = new byte[length];

            insputStream.read(bytes);
            insputStream.close();
                
            Compression (bytes);
        }
        catch (Exception e) 
        {
    			return;
        }

        

        
    }
}

