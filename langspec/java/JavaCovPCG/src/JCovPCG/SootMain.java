package JCovPCG;

import soot.Scene;
import soot.options.Options;

import java.util.ArrayList;
import java.util.List;

import soot.PackManager;
import soot.Transform;
import soot.Transformer;

public class SootMain {

	private void initSoot (String strClassPath, String strCheckPath)
	{
		List<String> lstCheckPath = new ArrayList<String>();
		
		lstCheckPath.add(strCheckPath);	
		Options.v().set_process_dir(lstCheckPath);	
		//Options.v().set_whole_program(true);
		//Options.v().set_prepend_classpath(true);
		//Options.v().set_no_bodies_for_excluded(true);
		
		if (!strClassPath.isEmpty())
		{	
			Options.v().set_soot_classpath(Scene.v().defaultClassPath() + ";" + strClassPath);
		}
		
		Options.v().set_output_format(Options.output_format_class);
		//Options.v().set_output_format(Options.output_format_jimple);
		
		System.out.println ("soot class path: " + Scene.v().getSootClassPath());	
	}
	
	private void runSoot (Object oTransObj, String strPhaseName)
	{
		PackManager.v().getPack("jtp").add(new Transform(strPhaseName, (Transformer) oTransObj));
		
		System.out.println ("start load class...");
		
		Scene.v().loadNecessaryClasses();
		
		System.out.println ("start run packs...");
	    PackManager.v().runPacks();
	    
	    System.out.println ("start output...");
		
		/* write jimple */
		PackManager.v().writeOutput();
		
		return;
	}
}
