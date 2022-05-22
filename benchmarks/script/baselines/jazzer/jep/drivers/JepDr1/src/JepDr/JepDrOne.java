
package JepDr;

import jep.Jep;
import jep.JepConfig;
import jep.Interpreter;
import jep.SubInterpreter;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import java.io.IOException;


public class JepDrOne {

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

        JepConfig config = new JepConfig();
        config.addIncludePaths("subprocess");
        
        Interpreter interp = new SubInterpreter(config);
        interp.runScript(seed);
    }

}

