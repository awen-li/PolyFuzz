package JCovPCG;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.ParseException;

import java.io.File;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.FileInputStream;

public class Main {

private
	static Options Ops = new Options ();

    Main ()
    {
    	initOptions ();
    }
    
	private void initOptions ()
	{
	    Option op = new Option ("d", "dependences", true, "the target's dependence list");
	    op.setRequired(true);
	    Ops.addOption(op);
	    
	    op = new Option ("t", "target", true, "the target's dir");
	    op.setRequired(true);
	    Ops.addOption(op);
	    
	    return;
	}
    
	public CommandLine getCmd (String[] args)
	{
		CommandLine Cmd = null;
		
		CommandLineParser parser = new DefaultParser ();
        try
        {
            Cmd = parser.parse(Ops, args);
        }
        catch (ParseException e)
        {
        	System.out.println (e.getMessage());
        	System.exit(1);        	
        }
        
		return Cmd;
	}
	
	public String loadDependecs (String fileName)
	{
		String DepStrs = "";
		
		try
		{
			File FD = new File (fileName);
			InputStreamReader RD = new InputStreamReader (new FileInputStream (FD));
			BufferedReader BR    = new BufferedReader (RD);
			
			String line = "";
			while ((line = BR.readLine()) != null)
			{
				DepStrs += line + ";";
			}
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
		
		return DepStrs;	
	}
	
	
	public static void main(String[] args) 
	{	
		Main M = new Main ();
		CommandLine Cmd = M.getCmd (args);

		String strDeps = M.loadDependecs(Cmd.getOptionValue("dependences"));
		String targetPath  = M.loadDependecs(Cmd.getOptionValue("target"));
		if (targetPath.isEmpty())
		{
			System.out.println ("Please input the target to be instrumented...!");
        	System.exit(1);			
		}
		
		SootMain SM = new SootMain (strDeps, targetPath);
		SM.runSoot ();
	}

}
