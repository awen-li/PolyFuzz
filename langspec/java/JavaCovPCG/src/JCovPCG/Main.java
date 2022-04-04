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
	static int BlockID = 1;

    Main ()
    {
    	initOptions ();
    }
    
	private void initOptions ()
	{
	    Option op = new Option ("d", "dependences", true, "the target's dependence list");
	    op.setRequired(false);
	    Ops.addOption(op);
	    
	    op = new Option ("t", "target", true, "the target's dir");
	    op.setRequired(true);
	    Ops.addOption(op);
	    
	    op = new Option ("j", "jimple", false, "generate jimples");
	    op.setRequired(false);
	    Ops.addOption(op);
	    
	    op = new Option ("b", "blockid", true, "initial blockid");
	    op.setRequired(false);
	    Ops.addOption(op);
	    
	    op = new Option ("p", "print", false, "print debug info");
	    op.setRequired(false);
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
	
	public String readFile (String fileName, boolean isMultiple)
	{
		String results = "";
		try
		{
			if (fileName == null)
			{
				return results;
			}
			
			System.out.println ("readFile -> fileName = " + fileName);
		
			File FD = new File (fileName);
			InputStreamReader RD = new InputStreamReader (new FileInputStream (FD));
			BufferedReader BR    = new BufferedReader (RD);
			
			if (isMultiple == true)
			{			
				String line = "";
				while ((line = BR.readLine()) != null)
				{
					results += line + ";";
				}
			}
			else
			{
				results = BR.readLine();		
			}
		}
		catch (Exception e)
		{
			return null;
		}
		
		return results;
	}
	
	public String loadDependecs (String fileName)
	{	
		return readFile (fileName, true); 
	}
	
	public int initBlockId (String strBlockId)
	{
		int BlockId = 16383;
		if (strBlockId != null && !strBlockId.isEmpty())
		{
			BlockId = Integer.parseInt(strBlockId);
		}
		
		String extId = readFile ("INTERAL_LOC", false);
		if (extId != null && !extId.isEmpty())
		{
			BlockId = Integer.parseInt(extId);
		}
		
		return BlockId;
	}
	
	
	public static void main(String[] args) 
	{	
		Main M = new Main ();
		CommandLine Cmd = M.getCmd (args);
		
		String strBlockId     = Cmd.getOptionValue("blockid");
		String strDeps        = M.loadDependecs(Cmd.getOptionValue("dependences"));
		String targetPath     = Cmd.getOptionValue("target");
		
		if (targetPath == null || targetPath.isEmpty())
		{
			System.out.println ("Please input the target to be instrumented...!");
        	System.exit(1);			
		}
	
		System.out.println ("targetPath = " + targetPath);
		
		int BlockId = M.initBlockId (strBlockId);
		
		int PrintJimple = 0;
		if (Cmd.hasOption("j"))
		{
			PrintJimple = 1;
		}
		
		if (Cmd.hasOption("p"))
		{
			Debug.SetDebug(true);
		}
			
		SootMain SM = new SootMain (strDeps, targetPath, BlockId, PrintJimple);
		SM.runSoot ();
	}

}
