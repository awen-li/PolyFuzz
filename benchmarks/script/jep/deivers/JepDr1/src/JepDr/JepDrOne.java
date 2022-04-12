package JepDr;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import jep.Interpreter;
import jep.MainInterpreter;
import jep.SharedInterpreter;

public class JepDrOne {

	public static void main(String args[]) throws Exception 
	{
        Process p = Runtime.getRuntime().exec("python python/jep_path.py");
        BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String ret = in.readLine();
        System.out.println("the jep's built C library is at: "+ret);
        MainInterpreter.setJepLibraryPath(ret);
        Interpreter interp = new SharedInterpreter();
        interp.exec("print('hello world')");
    }

}
