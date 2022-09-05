import com.github.luben.zstd.Zstd;

public class CompressTest {
    
    public static void fuzzerTestOneInput(byte[] input)
    {
        try
        {
            byte[] compressed = Zstd.compress(input);
            
        }
        catch (Exception e) 
        {
            return;
        }      
    }
}
