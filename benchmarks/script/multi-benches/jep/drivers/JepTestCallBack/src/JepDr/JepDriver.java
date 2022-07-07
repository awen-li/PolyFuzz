package JepDr;

import jep.Jep;
import jep.JepConfig;
import jep.Interpreter;
import jep.SubInterpreter;


public class JepDriver {

    public void run(String argv[]) 
    {
        try 
        {
            String spt = argv [0];

            JepConfig config = new JepConfig();
            config.addIncludePaths("subprocess");
            
            Interpreter interp = new SubInterpreter(config);
            interp.runScript(spt);

            interp.set("test",argv [1]);
            interp.getValue("test");

            Callback(spt)

        }
        catch (Exception e) 
        {
            return;
        }

    }

    // get the jep used for this class
    public Interpreter Callback(string str) {
        return str;
    }

    public static void main(String argv[]) throws Throwable 
    {
        JepDriver jep_drive = new JepDriver();
        jep_drive.run(argv);
    }


}
