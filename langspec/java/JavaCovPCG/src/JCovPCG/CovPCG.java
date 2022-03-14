
package JCovPCG;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Iterator;

import soot.Body;
import soot.BodyTransformer;
import soot.Local;
import soot.toolkits.graph.Block;
import soot.toolkits.graph.BlockGraph;
import soot.toolkits.graph.BriefBlockGraph;

import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.jimple.ConditionExpr;
import soot.jimple.EqExpr;
import soot.jimple.IfStmt;
import soot.jimple.IntConstant;
import soot.jimple.Jimple;
import soot.jimple.NeExpr;
import soot.jimple.ReturnStmt;
import soot.jimple.ReturnVoidStmt;
import soot.jimple.Stmt;
import soot.jimple.SwitchStmt;
import soot.util.Chain;


public class CovPCG extends BodyTransformer 
{
	/* internal counter fields */
	static SootClass DynTrace = Scene.v().loadClassAndSupport("JCovPCG.DynTrace");
	
	static SootMethod JvTrace       = DynTrace.getMethodByName("JvTrace");
	static SootMethod JvTraceD8     = DynTrace.getMethodByName("JvTraceD8");
	static SootMethod JvTraceD16    = DynTrace.getMethodByName("JvTraceD16");
	static SootMethod JvTraceD32    = DynTrace.getMethodByName("JvTraceD32");
	static SootMethod JvTraceD64    = DynTrace.getMethodByName("JvTraceD64");
	static SootMethod JvTraceInit   = DynTrace.getMethodByName("JvTraceInit");
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
	
	private int GetStmtID (Map<Stmt, Integer> StmtIDMap, Map<Integer, Stmt> ID2StmpMap, Stmt CurSt)
	{
		int StID = 0;
		if (!StmtIDMap.containsKey (CurSt))
		{
			StID = StmtIDMap.size() + 1;
			StmtIDMap.put(CurSt, StID);
			ID2StmpMap.put(StID, CurSt);
		}
		else
		{
			StID = StmtIDMap.get(CurSt);
		}
		return StID;
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
	
	private String ValueType (Value V)
	{
		String ValueType = "";
		if (V.getType() instanceof soot.IntType)
		{
			ValueType = "#i";				
		}
		else
		{
			ValueType = "#o";
		}
		
		return ValueType;
	}
	
	private String ValueName (Value V)
	{
		String Name = V.toString();
		if (Name.indexOf(" ") != -1)
		{
			return "";
		}
		
		return Name;
	}
	
	private void GenBranchVar (IfStmt CurSt)
	{
		ConditionExpr expr = (ConditionExpr) CurSt.getCondition();
		boolean isTargetIf = false;
		if (((expr instanceof EqExpr) || (expr instanceof NeExpr))) 
		{
			if (expr.getOp1() instanceof Local && expr.getOp2() instanceof Local) {
				isTargetIf = true;
			}
		}
		
		return;
	}
	
	private void InstrumentSAI (Chain units, int BlockID, Unit SAISt)
	{
		List<ValueBox> DefValues =  SAISt.getDefBoxes();
		if (DefValues.size() == 0)
		{
			return;
		}
		
		Stmt dynStmt = null;
		Value Def = DefValues.get(0).getValue();
		
		Value BID = IntConstant.v(BlockID);
		Value ValueKey = IntConstant.v(Def.hashCode());		
		if (Def.getType() instanceof soot.ByteType)
		{
			dynStmt = Jimple.v().newInvokeStmt(Jimple.v().newStaticInvokeExpr(JvTraceD8.makeRef(), BID, ValueKey, Def));
		}
		else if (Def.getType() instanceof soot.ShortType)
		{
			dynStmt = Jimple.v().newInvokeStmt(Jimple.v().newStaticInvokeExpr(JvTraceD16.makeRef(), BID, ValueKey, Def));
		}
		else if (Def.getType() instanceof soot.IntType)
		{
			dynStmt = Jimple.v().newInvokeStmt(Jimple.v().newStaticInvokeExpr(JvTraceD32.makeRef(), BID, ValueKey, Def));
		}
		else if (Def.getType() instanceof soot.LongType)
		{
			dynStmt = Jimple.v().newInvokeStmt(Jimple.v().newStaticInvokeExpr(JvTraceD64.makeRef(), BID, ValueKey, Def));
		}
		else
		{
			return;
		}
			
	    units.insertAfter(dynStmt, SAISt);	    
	    System.out.println("\tInstrument SAI statement -> " + dynStmt.toString());	
	}
	
	
	/* SA-IR
	 * Type: i: integer, o: other 
	 *  compare statement: ID:CMP:DEF#T:USE1#T:USE2#T:...:USEN#T
	 *  other statement: 
	 * */
	private String GetSaIR (Map<Stmt, Integer> Stmt2IDMap, Map<Integer, Stmt> ID2StmpMap, Unit CurUnit)
	{
		String SaIR = "";
		Stmt CurSt = (Stmt)CurUnit;
		
		if(CurSt instanceof IfStmt)
		{
			SaIR += "CMP:";
		}
		else if(CurSt instanceof SwitchStmt)
		{
			SaIR += "SWITCH:";
		}
        else
        {
            SaIR += ":";
        }
		
		List<ValueBox> DefValues =  CurSt.getDefBoxes();
		if (DefValues.size() != 0)
		{
			Value Def = DefValues.get(0).getValue();
			String Name = ValueName (Def);
			if (Name != "")
			{
				SaIR += Name + ValueType (Def);
			}
		}
		SaIR += ":";
		
		List<ValueBox> RefValues =  CurSt.getUseBoxes();
		for (ValueBox VB : RefValues) 
		{
			Value Use = VB.getValue();
			String Name = ValueName (Use);
			if (Name != "")
			{
				SaIR += Name + ValueType (Use) + ":";
			}		
		}
		
		if (SaIR.length() < 4)
		{
			return "";
		}
		
		int StID = GetStmtID (Stmt2IDMap, ID2StmpMap, CurSt);
		return  Integer.toString(StID) + ":" + SaIR;
	}
	
	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	protected void internalTransform(Body body, String phaseName, Map<String, String> options) {
		
		Map<Block, Integer> Block2ID  = new HashMap<>();
		Map<Stmt, Integer> Stmt2IDMap = new HashMap<>();
		Map<Integer, Stmt> ID2StmtMap = new HashMap<>();
		
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
			
			int CurBId = Block2ID.get(CurB);
			
			/* for each block, translate the statement to SA-IR */
			System.out.println("### Block -> " + CurBId);
			for (Unit CurUnit : CurB)
			{
			    System.out.println("\t statement ->  " + CurUnit.toString());
				String SaIR = GetSaIR (Stmt2IDMap, ID2StmtMap, CurUnit);
				PCGuidance.pcgInsertIR(CFGHd, CurBId, SaIR);
			}
			
			List<Block> Succs = CurB.getSuccs();
			for (Block su: Succs)
			{
				wfQueue.add (su);
				PCGuidance.pcgCFGEdge(CFGHd, CurBId, Block2ID.get(su));
			}		
		}	
		PCGuidance.pcgBuild(CFGHd);
		
		/* start to instrument with PCG */
		Chain units = body.getUnits();
		for (Block CurB : Block2ID.keySet())
		{
			System.out.println("@@@ Block -> " + Block2ID.get(CurB).toString());
			Unit InstrmedStmt = CurB.getTail();

			int BID = Block2ID.get(CurB);
			if (PCGuidance.pcgNeedInstrumented(CFGHd, BID) == false)
			{
				continue;
			}
			
			int StmtID = PCGuidance.pcgGetPCGStmtID(CFGHd, BID);
			if (StmtID != 0)
			{
				if (ID2StmtMap.containsKey(StmtID) == false)
				{
					System.out.println("\t[PCG]Not contains key -> " + StmtID);
					continue;
				}
				
				InstrmedStmt = ID2StmtMap.get(StmtID);
				InstrumentSAI (units, BID, InstrmedStmt);
			}
			else
			{
				/* instrument before the tail statement */
				Stmt dynStmt = Jimple.v().newInvokeStmt(Jimple.v().newStaticInvokeExpr(JvTrace.makeRef(), IntConstant.v(BID)));
				units.insertBefore(dynStmt, InstrmedStmt);
				System.out.println("\tInstrument before statement -> " + InstrmedStmt.toString());
			}			
		}
		
		/* start to instrument with SAI */
		int[] AllSAIStmtIDs = PCGuidance.pcgGetAllSAIStmtIDs(CFGHd);
		for (int ix = 0, Size= AllSAIStmtIDs.length; ix < Size; ix++)
		{
		    int StmtID = AllSAIStmtIDs [ix];
		    if (ID2StmtMap.containsKey(StmtID) == false)
		    {
		    	System.out.println("\t[SAI]Not contains key -> " + StmtID);
		    	continue;
		    }

		    Unit InstrmedStmt = ID2StmtMap.get(StmtID);
		    InstrumentSAI (units, 0, InstrmedStmt);
		}
		
		PCGuidance.pcgCFGDel(CFGHd);
        System.out.println("@@@ instrumenting method : " + CurMethod.getSignature() + " done!!!");
	}
}
