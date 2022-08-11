import com.sun.jna.Library;
import com.sun.jna.Native;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class loadLibrary{

    public static void fuzzerTestOneInput(FuzzedDataProvider data)
    {
        String input = data.consumeRemainingAsString();
        try 
        {
            new Native.loadLibrary(input, CRuntimeLibrary.class);
        } 
        catch () 
        {
            return;
        }
    }
}