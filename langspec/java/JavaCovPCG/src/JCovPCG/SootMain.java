package JCovPCG;

import soot.Scene;
import soot.options.Options;

import java.util.ArrayList;
import java.util.List;

import soot.PackManager;
import soot.Transform;
import soot.Transformer;

public class SootMain {
	
	private int StartBlockID = 0;
	private int printJimple = 0;
	
	SootMain (String strDeps, String targetPath, int StartBID, int printJimple)
	{
		StartBlockID = StartBID;
		this.printJimple  = printJimple;
		
		initSoot (strDeps, targetPath);	
	}

	private void initSoot (String strDeps, String targetPath)
	{
		List<String> lstCheckPath = new ArrayList<String>();
		
		lstCheckPath.add(targetPath);	
		Options.v().set_process_dir(lstCheckPath);	
		//Options.v().set_whole_program(true);
		//Options.v().set_prepend_classpath(true);
		//Options.v().set_no_bodies_for_excluded(true);
		
		if (strDeps != null && !strDeps.isEmpty())
		{	
			Options.v().set_soot_classpath(Scene.v().defaultClassPath() + ";" + strDeps);
		}
		
		Options.v().set_output_format(Options.output_format_class);
		
		if (printJimple != 0)
		{
		    Options.v().set_output_format(Options.output_format_jimple);
		}
		
		System.out.println ("soot class path: " + Scene.v().getSootClassPath());	
	}
	
	public void runSoot ()
	{
		PackManager.v().getPack("jtp").add(new Transform("jtp.InstmPCG", (Transformer) new CovPCG (StartBlockID)));
		
		System.out.println ("runSoot start...");
		
		Scene.v().loadNecessaryClasses();
		
		System.out.println ("start run packs...");
	    PackManager.v().runPacks();
	    
	    System.out.println ("start output...");
		
		/* write jimple */
		PackManager.v().writeOutput();
		
		System.out.println ("runSoot done...");
		return;
	}
}
