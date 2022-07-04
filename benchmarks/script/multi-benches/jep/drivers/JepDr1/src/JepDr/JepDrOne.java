package JepDr;

import jep.Jep;
import jep.JepConfig;
import jep.Interpreter;
import jep.SubInterpreter;

public class JepDriver {

    public static void main(String argv[]) throws Throwable 
    {
        try 
        {
            String spt = argv [0];

            JepConfig config = new JepConfig();
            config.addIncludePaths("subprocess");
            
            Interpreter interp = new SubInterpreter(config);
            interp.runScript(spt);
        }
        catch (Exception e) 
        {
            return;
        }
    }

}
