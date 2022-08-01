import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import jep.Interpreter;
// import jep.SubInterpreter;
// import jep.JepConfig;
import java.io.File;
import jepTest.TestSharedInterpreter;

class ResultIsNotEqualException extends Exception
{
    public ResultIsNotEqualException(String msg)
    {
        super(msg);
    }
}

public class JepJazzerTest {

    static File pwd;
    static Interpreter interp;

    public static void fuzzerInitialize()
    {
        // pwd = new File(".");
        // interp = new SubInterpreter(new JepConfig().addIncludePaths(pwd.getAbsolutePath()));
        // interp.exec("import pyTest");
    }
    
    public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Throwable {

        try {

            int input = data.consumeInt();

            
            // any of the following work, these are just pseudo-examples
        
            // using exec(String) to invoke methods
            // interp.set("arg1", input);
            // interp.set("arg2", input + 2);
            // interp.exec("x = pyTest.calc_add(arg1, arg2)");
            // //Object output = interp.getValue("x");
            // interp.getValue("x");

            try {
                TestSharedInterpreter.test(input);
            } catch (Exception e) {
                throw new ResultIsNotEqualException("The thread is incorrect" + e);
            }

            // if(output != (input * 2 + 2))
            // {
            //     throw new ResultIsNotEqualException("The Result are incorrect");
            // }
        
        }
        catch (Exception e) 
        {
            System.out.println("An error has occored" + e);
            return;
        }

    }

}
