package JepDr;


import jep.Interpreter;
import jep.JepConfig;
import jep.SubInterpreter;
import jep.MainInterpreter;
import jep.SharedInterpreter;

public class JepDrOne {

    static String JepPath="/root/anaconda3/lib/python3.9/site-packages/jep/libjep.so";
    
    public static void main(String args[]) throws Exception 
    {
        JepConfig config = new JepConfig();
        config.addIncludePaths("subprocess");

        System.out.println ("1111111111111111111111111");
        try (Interpreter interp = new SubInterpreter(config)) {
            System.out.println ("1.1.1.1.1.1.1.1.1.1.1.");
            interp.eval("from invoke_args import *");
        
            System.out.println ("22222222222222222222222222222");
            Object result = interp.invoke("invokeNoArgs");
            if (result != null) {
                throw new IllegalStateException("Received " + result + " but expected null");
            }

            System.out.println ("33333333333333333333333333333");

            // test a basic invoke with arguments
            result = interp.invoke("invokeArgs", "a", null, 5.4);
            if (result == null || !result.equals(Boolean.TRUE)) {
                throw new IllegalStateException("Received " + result + " but expected true");
            }

            System.out.println ("44444444444444444444444444444");
        }catch (Exception e) {
            e.printStackTrace();
        }
    }

}
