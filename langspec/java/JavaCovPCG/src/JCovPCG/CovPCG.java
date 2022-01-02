
package JCovPCG;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

import soot.Body;
import soot.BodyTransformer;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.graph.Block;
import soot.toolkits.graph.BlockGraph;
import soot.toolkits.graph.BriefBlockGraph;
import soot.toolkits.graph.CompleteBlockGraph;
import soot.toolkits.graph.CompleteUnitGraph;

import soot.Local;
import soot.RefType;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.Jimple;
import soot.jimple.Stmt;
import soot.jimple.StringConstant;
import soot.util.Chain;


public class CovPCG extends BodyTransformer 
{
	/* internal counter fields */
	static SootClass DynTrace = Scene.v().loadClassAndSupport("JCovPCG.DynTrace");
	
	static SootMethod JvTrace = DynTrace.getMethodByName("JvTrace");
	static SootMethod JvTraceInit = DynTrace.getMethodByName("JvTraceInit");
	
	static int StartBID = 0;
	
	CovPCG (int StartBID)
	{
		CovPCG.StartBID = StartBID;
	}
	
	@Override
	protected void internalTransform(Body body, String phaseName, Map<String, String> options) {
		
		SootMethod CurMethod = body.getMethod();		
		System.out.println("instrumenting method : " + CurMethod.getSignature());

		boolean isMainMethod = CurMethod.getSubSignature().equals("void main(java.lang.String[])");
		if (isMainMethod)
		{
			System.out.println("@@@ Get to the main...");
		}
		
		/* unit graph */
		BlockGraph BG = new BriefBlockGraph(body);
		List<Block> LB = BG.getBlocks();

		for (Block b:LB) 
		{
			StartBID++;
			System.out.println("BlockID : " + String.valueOf(StartBID));
			
			Iterator<Unit> unitsIt = b.iterator();
			while (unitsIt.hasNext()) 
			{
			    Unit unit = unitsIt.next();
                System.out.println("\tstatement -> " + unit.toString());
			}
		}
		
		
	}
}
