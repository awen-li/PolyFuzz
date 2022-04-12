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
        System.out.println ("00000000000000000000000000");
        JepConfig config = new JepConfig();
        config.addIncludePaths("../subprocess");

        System.out.println ("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        try (Interpreter interp = new SubInterpreter(config)) {
            interp.eval("from invoke_args import *");
        }catch (Exception e) {
            e.printStackTrace();
        }
        
        System.out.println ("11111111111111");
        MainInterpreter.setJepLibraryPath(JepPath);

        System.out.println ("2222222222222");
        Interpreter interp = new SharedInterpreter();

        System.out.println ("33333333333333");
        interp.exec("print('hello world')");

        System.out.println ("4444444444444");
    }

}
