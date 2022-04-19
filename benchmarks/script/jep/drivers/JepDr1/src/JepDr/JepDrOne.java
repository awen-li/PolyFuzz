package JepDr;


import jep.Interpreter;
import jep.JepConfig;
import jep.SubInterpreter;
import jep.MainInterpreter;
import jep.SharedInterpreter;

public class JepDrOne {
    
    public static void main(String args[]) throws Exception 
    {
        JepConfig config = new JepConfig();
        config.addIncludePaths("subprocess");

        try (Interpreter interp = new SubInterpreter(config)) {

            interp.eval("from invoke_args import *");

            Object result = interp.invoke("invokeNoArgs");
            if (result != null) {
                throw new IllegalStateException("Received " + result + " but expected null");
            }

            // test a basic invoke with arguments
            result = interp.invoke("invokeArgs", "a", null, 5.4);
            if (result == null || !result.equals(Boolean.TRUE)) {
                throw new IllegalStateException("Received " + result + " but expected true");
            }

        }catch (Exception e) {
            e.printStackTrace();
        }
    }

}
