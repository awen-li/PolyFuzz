
package JCovPCG;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Iterator;

import soot.Body;
import soot.BodyTransformer;
import soot.toolkits.graph.Block;
import soot.toolkits.graph.BlockGraph;
import soot.toolkits.graph.BriefBlockGraph;

import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.IntConstant;
import soot.jimple.Jimple;
import soot.jimple.ReturnStmt;
import soot.jimple.ReturnVoidStmt;
import soot.jimple.Stmt;
import soot.util.Chain;


public class CovPCG extends BodyTransformer 
{
	/* internal counter fields */
	static SootClass DynTrace = Scene.v().loadClassAndSupport("JCovPCG.DynTrace");
	
	static SootMethod JvTrace = DynTrace.getMethodByName("JvTrace");
	static SootMethod JvTraceInit = DynTrace.getMethodByName("JvTraceInit");
	static SootMethod JvTraceDeInit = DynTrace.getMethodByName("JvTraceDeInit");
	
	static int StartBID = 0;
	static Map<String, Integer> BlackList;
	
	CovPCG (int StartBID)
	{
		CovPCG.StartBID = StartBID;
		InitBlackList ();
	}
	
	private synchronized int GetGuaranteeID ()
	{
		int GID = StartBID++;
		return GID;
	}
	
	private void InitBlackList ()
	{
		BlackList = new HashMap<>();
		
		BlackList.put("public void <init>()", 1);
        BlackList.put("static void <clinit>()", 1);
	}
	
	private int GetStmtID (Map<Stmt, Integer> StmtIDMap, Stmt CurSt)
	{
		int StID = 0;
		if (!StmtIDMap.containsKey (CurSt))
		{
			StID = StmtIDMap.size();
			StmtIDMap.put(CurSt, StID);
		}
		else
		{
			StID = StmtIDMap.get(CurSt);
		}
		return StID;
	}
	
	private boolean IsInBlackList (String FuncName)
	{
	    System.out.println("@@@ IsInBlackList: " + FuncName);
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
			int GID = GetGuaranteeID ();
			Block2ID.put(b, GID);
		}
	}
	
	private boolean IsExitStmt (Stmt stmt, boolean isMainMethod)
	{	
		if (stmt.toString().indexOf("java.lang.System: void exit(int)") != -1)
		{
			return true;
		}
		
		if (isMainMethod && (stmt instanceof ReturnStmt || stmt instanceof ReturnVoidStmt))
		{
		    return true;
		}
		
		return false;
	}
	
	private boolean IsExcepProc (Stmt stmt)
	{
		if (stmt.toString().indexOf("caughtexception") != -1)
		{
			return true;
		}
		
		return false;
	}
	
	private void InsertExitStmt (Body body, boolean isMainMethod)
	{
		Chain units = body.getUnits();
		Iterator stmtIt = units.snapshotIterator();

		while (stmtIt.hasNext()) 
		{
			Stmt stmt = (Stmt) stmtIt.next();
			
			if (IsExcepProc (stmt))
			{
				Stmt dynStmt = Jimple.v().newInvokeStmt(Jimple.v().newStaticInvokeExpr(JvTraceDeInit.makeRef(), IntConstant.v(100)));
		    	units.insertBefore(dynStmt, stmt);
		    	System.out.println("\t### Instrument exit statement with exit-code 100 -> " + stmt.toString());
			}
			else if (IsExitStmt (stmt, isMainMethod))
		    {
		    	Stmt dynStmt = Jimple.v().newInvokeStmt(Jimple.v().newStaticInvokeExpr(JvTraceDeInit.makeRef(), IntConstant.v(0)));
		    	units.insertBefore(dynStmt, stmt);
		    	System.out.println("\t### Instrument exit statement with exit-code 0 -> " + stmt.toString());
		    }
		}	
	}
	
	private String GetSaIR (Map<Stmt, Integer> StmtIDMap, Unit CurUnit)
	{
		Stmt CurSt = (Stmt)CurUnit;
		
		int StID = GetStmtID (StmtIDMap, CurSt);
		return Integer.toString(StID);
	}
	
	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	protected void internalTransform(Body body, String phaseName, Map<String, String> options) {
		
		Map<Block, Integer> Block2ID = new HashMap<>();
		Map<Stmt, Integer> StmtIDMap = new HashMap<>();
		
		SootMethod CurMethod = body.getMethod();		
		System.out.println("@@@ instrumenting method : " + CurMethod.getSignature());
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
		
		/* insert exit function */
		InsertExitStmt (body, isMainMethod);
		
		/* init block-id */
		InitBlockMap (Block2ID, BG.getBlocks());
		
	    /* init CFG and compute dominance */	
		List<Block> wfQueue = new ArrayList<Block>();	
		wfQueue.add(Heads.get(0));
		
		int CFGHd = PCGuidance.pcgCFGAlloct(Block2ID.get(Heads.get(0)));		
		while (!wfQueue.isEmpty())
		{
			Block CurB= wfQueue.get(0);
			wfQueue.remove(0);
			
			/* for each block, translate the statement to SA-IR */
			System.out.println("### Block -> " + Block2ID.get(CurB).toString());
			for (Unit CurUnit : CurB)
			{
				if (CurUnit.hashCode() == 0)
				{
					System.out.println("\t Not code....statement ->  " + CurUnit.toString());
					continue;
				}
				String SaIR = GetSaIR (StmtIDMap, CurUnit);
				System.out.println("\t statement ->  " + CurUnit.toString() + ", SA-IR: " + SaIR);
			}
			
			List<Block> Succs = CurB.getSuccs();
			for (Block su: Succs)
			{
				wfQueue.add (su);
				PCGuidance.pcgCFGEdge(CFGHd, Block2ID.get(CurB), Block2ID.get(su));
			}		
		}	
		PCGuidance.pcgBuild(CFGHd);
		
		/* start to instrument with PCG */
		Chain units = body.getUnits();
		for (Block CurB : Block2ID.keySet())
		{
			System.out.println("### Block -> " + Block2ID.get(CurB).toString());
			Unit TailStmt = CurB.getTail();

			int BID = Block2ID.get(CurB);
			if (PCGuidance.pcgNeedInstrumented(CFGHd, BID) == false)
			{
				continue;
			}
			
			/* instrument before the tail statement */
			Stmt dynStmt = Jimple.v().newInvokeStmt(Jimple.v().newStaticInvokeExpr(JvTrace.makeRef(), IntConstant.v(BID)));
			units.insertBefore(dynStmt, TailStmt);
			
			System.out.println("\tInstrument before statement -> " + TailStmt.toString());
		}
		
		PCGuidance.pcgCFGDel(CFGHd);
        System.out.println("@@@ instrumenting method : " + CurMethod.getSignature() + " done!!!");
	}
}
