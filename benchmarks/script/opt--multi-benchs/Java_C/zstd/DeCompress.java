import com.github.luben.zstd.Zstd;

public class CompressTest {
    
    public static void fuzzerTestOneInput(byte[] input)
    {
        try
        {
            int length   = input.length;
            byte[] ob = new byte[length];
            Zstd.decompress(ob, bytes); 
        }
        catch (Exception e) 
        {
            return;
        }      
    }
}
