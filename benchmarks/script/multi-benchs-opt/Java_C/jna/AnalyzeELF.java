import java.io.IOException;
import com.sun.jna.ELFAnalyser;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;


public class AnalyzeELF 
{
    public static void WritOneCase (String Path, byte[] bytes)
    {
        try
        {
            Path p = Paths.get(Path);
            Files.write(p, bytes);
        }
        catch (IOException e) 
        {
            return;
        }
    }

    public static void fuzzerTestOneInput(byte[] input)
    {
        String seed = "seed";
        
        WritOneCase (seed, input);

        try
        {
            ELFAnalyser.analyse(seed);
        }
        catch (IOException e) 
        {
            return;
        }
    }
}

