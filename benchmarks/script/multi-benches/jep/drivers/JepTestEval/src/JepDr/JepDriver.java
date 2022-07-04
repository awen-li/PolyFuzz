package JepDr;

import jep.Jep;
import jep.JepConfig;
import jep.Interpreter;
import jep.SubInterpreter;

public class JepTestEval {
    
    public void run(String argv[]) 
    {
        try 
        {
            String spt = argv [0];

            JepConfig config = new JepConfig();
            config.addIncludePaths("subprocess");
            
            Interpreter interp = new SubInterpreter(config);
            interp.runScript(spt);

            //test eval
            interp.eval(argv [1]);

        }
        catch (Exception e) 
        {
            return;
        }

    }

    public static void main(String argv[]) throws Throwable 
    {
        JepTestEval jep_drive = new JepTestEval();
        jep_drive.run(argv);
    }

}
