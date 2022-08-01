import com.github.luben.zstd.Zstd;

public class CompressTest {
    
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
