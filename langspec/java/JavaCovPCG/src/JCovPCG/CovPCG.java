
package JCovPCG;

import java.util.ArrayList;
import java.util.HashMap;
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
import soot.jimple.IntConstant;
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
	static Map<String, Integer> BlackList;
	
	CovPCG (int StartBID)
	{
		CovPCG.StartBID = StartBID;
		InitBlackList ();
	}
	
	private void InitBlackList ()
	{
		BlackList = new HashMap<>();
		
		BlackList.put("public void <init>()", 1);
	}
	
	private boolean IsInBlackList (String FuncName)
	{
		if (BlackList.get(FuncName) == null)
		{
			return false;
		}
		else
		{
			return true;
		}
	}
	
	private void InitBlockMap (Map<Block, Integer> Block2ID, List<Block> LB)
	{
		for (Block b:LB) 
		{
			StartBID++;
			Block2ID.put(b, StartBID);
		}
	}
	
	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	protected void internalTransform(Body body, String phaseName, Map<String, String> options) {
		
		Map<Block, Integer> Block2ID = new HashMap<>();
		
		SootMethod CurMethod = body.getMethod();		
		System.out.println("instrumenting method : " + CurMethod.getSignature());
		if (IsInBlackList (CurMethod.getDeclaration()))
		{
			return;
		}
		
		/* unit graph */
		BlockGraph BG = new BriefBlockGraph(body);
		List<Block> Heads = BG.getHeads();
		
		/* main function: init fuzzing environment */
		boolean isMainMethod = CurMethod.getSubSignature().equals("void main(java.lang.String[])");
		if (isMainMethod)
		{
			Chain units = body.getUnits();
			Stmt dynStmt = Jimple.v().newInvokeStmt(Jimple.v().newStaticInvokeExpr(JvTraceInit.makeRef(), IntConstant.v(StartBID)));
			Block Hb = Heads.get(0);
			units.insertBefore(dynStmt, Hb.getTail());
		}
		
		/* init block-id */
		InitBlockMap (Block2ID, BG.getBlocks());
		
	    /* init CFG and compute dominance */	
		List<Block> wfQueue = new ArrayList<Block>();	
		wfQueue.add(Heads.get(0));
		PCGuidance.pcgCFGAlloct(Block2ID.get(Heads.get(0)));		
		while (!wfQueue.isEmpty())
		{
			Block CurB= wfQueue.get(0);
			wfQueue.remove(0);
			
			List<Block> Succs = CurB.getSuccs();
			for (Block su: Succs)
			{
				wfQueue.add (su);
				PCGuidance.pcgCFGEdge(Block2ID.get(CurB), Block2ID.get(su));
			}		
		}	
		PCGuidance.pcgBuild();
		
		/* start to instrument with PCG */
		Chain units = body.getUnits();
		for (Block CurB : Block2ID.keySet())
		{
			System.out.println("Block -> " + Block2ID.get(CurB).toString());
			Unit TailStmt = CurB.getTail();
			System.out.println("\ttail-statement -> " + TailStmt.toString());
			
			int BID = Block2ID.get(CurB);
			if (PCGuidance.pcgNeedInstrumented(BID) == false)
			{
				continue;
			}
			
			/* instrument before the tail statement */
			Stmt dynStmt = Jimple.v().newInvokeStmt(Jimple.v().newStaticInvokeExpr(JvTrace.makeRef(), IntConstant.v(BID)));
			units.insertBefore(dynStmt, TailStmt);
		}
	}
}
