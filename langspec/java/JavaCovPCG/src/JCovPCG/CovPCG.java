
package JCovPCG;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
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
import soot.UnitBox;
import soot.Value;
import soot.ValueBox;
import soot.jimple.ConditionExpr;
import soot.jimple.Constant;
import soot.jimple.EqExpr;
import soot.jimple.GeExpr;
import soot.jimple.GtExpr;
import soot.jimple.IfStmt;
import soot.jimple.IntConstant;
import soot.jimple.Jimple;
import soot.jimple.LeExpr;
import soot.jimple.LookupSwitchStmt;
import soot.jimple.LtExpr;
import soot.jimple.NeExpr;
import soot.jimple.ReturnStmt;
import soot.jimple.ReturnVoidStmt;
import soot.jimple.Stmt;
import soot.jimple.SwitchStmt;
import soot.jimple.TableSwitchStmt;
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
	static String BranchVarFile = "branch_vars.bv";
    static String CmpStatFile = "cmp_statistic.info";
	
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

    private void DumpCmpStat (String FuncName, int BranchVarNum, int ConstBranchVarNum)
    {
        if (BranchVarNum == 0)
        {
            return;
        }
        try 
        {
            //function:brinstnum:CmpWithConstNum:CmpWithIntConstNum:CmpWithNoConstNum:CmpWithIntNoConstNum:CmpWithPointerConstNum
            BufferedWriter out = new BufferedWriter(new FileWriter(CmpStatFile, true));
            out.write(FuncName + ":" + Integer.toString(BranchVarNum) + ":" + Integer.toString(ConstBranchVarNum) + ":" + 
                      Integer.toString(BranchVarNum-ConstBranchVarNum)  + ":0:0:0\n");
            out.close();
					
		} catch (IOException e) 
        {
            e.printStackTrace();
        }
        
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
		if (FuncName.indexOf("<init>") != -1)
		{
			return true;
		}
		
		if (BlackList.get(FuncName) == null)
		{
			return false;
		}
		else
		{
			return true;
		}
	}
	
	private int InitBlockMap (Map<Block, Integer> Block2ID, List<Block> LB)
	{
	    int GID = 0;
		for (Block b:LB) 
		{
			GID = GetGuaranteeID ();
			Block2ID.put(b, GID);
		}

        return GID;
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
				//Stmt dynStmt = Jimple.v().newInvokeStmt(Jimple.v().newStaticInvokeExpr(JvTraceDeInit.makeRef(), IntConstant.v(100)));
		    	//units.insertAfter(dynStmt, stmt);
		    	//Debug.DebugPrint ("\t### Instrument exit statement with exit-code 100 -> " + stmt.toString());
			}
			else if (IsExitStmt (stmt, isMainMethod))
		    {
		    	Stmt dynStmt = Jimple.v().newInvokeStmt(Jimple.v().newStaticInvokeExpr(JvTraceDeInit.makeRef(), IntConstant.v(0)));
		    	units.insertBefore(dynStmt, stmt);
		    	Debug.DebugPrint ("\t### Instrument exit statement with exit-code 0 -> " + stmt.toString());
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
		if (V instanceof Constant) 
		{
			return "C";
		}
		
		String Name = V.toString();
		if (Name.indexOf(" ") != -1)
		{
			return "";
		}
		
		return Name;
	}
	
	private int GetCeCode (ConditionExpr CE)
	{
		if (CE instanceof EqExpr) return 32;
	    if (CE instanceof NeExpr) return 33;
		if (CE instanceof GtExpr) return 34;
		if (CE instanceof LtExpr) return 36;
		if (CE instanceof GeExpr) return 35;
		if (CE instanceof LeExpr) return 37;
		return 0;
	}
	
	/* Key:CMP:Predict:Value ------   1574118200:CMP:36:3 */
	private boolean GenIfStmtBv (IfStmt CurSt, List<Integer> BranchInfo) throws IOException
	{
		ConditionExpr CE = (ConditionExpr) CurSt.getCondition();
        
        int BranchNum = BranchInfo.get (0) + 1;
        BranchInfo.add (0, BranchNum);
		
		Value Op1 = CE.getOp1();
		Value Op2 = CE.getOp2();
		if (!(Op1.getType() instanceof soot.IntegerType) ||
			!(Op2.getType() instanceof soot.IntegerType))
		{
			return false;
		}

        int ConstBranchVarNum = BranchInfo.get (1) + 1;
        BranchInfo.add (0, ConstBranchVarNum);
		
		int Key;
		String Value;
		if (Op1 instanceof Constant) 
		{
			Key   = Op2.hashCode();
			Value = Op1.toString();	
		}
		else if (Op2 instanceof Constant)
		{
			Key   = Op1.hashCode();
			Value = Op2.toString();
		}
		else
		{
			return false;
		}
		
		int Predict = GetCeCode (CE);
		if (Predict == 0) return false;
				
		BufferedWriter out = new BufferedWriter(new FileWriter(BranchVarFile, true));
        out.write(Integer.toString(Key) + ":CMP:" + Integer.toString(Predict) + ":" + Value + "\n");
        out.close();
		
		return true;
	}
	
	private void GenSwitchStmtBv (Stmt CurSt, List<Integer> BranchInfo) throws IOException
	{
		if (CurSt instanceof TableSwitchStmt)
		{
		    int BranchNum = BranchInfo.get (0) + 1;
            BranchInfo.add (0, BranchNum);
            
		    int ConstBranchVarNum = BranchInfo.get (1) + 1;
            BranchInfo.add (1, ConstBranchVarNum);
            
			Debug.DebugPrint ("@@@ TableSwitchStmt\r\n");
			TableSwitchStmt Tss = (TableSwitchStmt) CurSt;
			
			int Key = Tss.getKey().hashCode();		
			int LowIndex  = Tss.getLowIndex();
			int HighIndex = Tss.getHighIndex();
			
			BufferedWriter out = new BufferedWriter(new FileWriter(BranchVarFile, true));
			while (LowIndex <= HighIndex)
			{
		        out.write(Integer.toString(Key) + ":SWITCH:" + Integer.toString(255) + ":" + Integer.toString(LowIndex) + "\n");
		        LowIndex++;	
			}
			out.close();
		}
		else if (CurSt instanceof LookupSwitchStmt)
		{
		    int BranchNum = BranchInfo.get (0) + 1;
            BranchInfo.add (0, BranchNum);
            
		    int ConstBranchVarNum = BranchInfo.get (1) + 1;
            BranchInfo.add (1, ConstBranchVarNum);
            
			Debug.DebugPrint ("@@@ LookupSwitchStmt\r\n");
			LookupSwitchStmt Lss = (LookupSwitchStmt)CurSt;
			
			int Key = Lss.getKey().hashCode();
			List<IntConstant> LIC = Lss.getLookupValues();
			BufferedWriter out = new BufferedWriter(new FileWriter(BranchVarFile, true));
			for (IntConstant IC : LIC)
			{
				out.write(Integer.toString(Key) + ":SWITCH:" + Integer.toString(255) + ":" + IC.toString() + "\n");
			}
			out.close();
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
	    Debug.DebugPrint ("\tInstrument SAI statement -> " + dynStmt.toString());	
	}
	
	
	/* SA-IR
	 * Type: i: integer, o: other 
	 *  compare statement: ID:CMP:DEF#T:USE1#T:USE2#T:...:USEN#T
	 *  other statement: 
	 * */
	private String GetSaIR (Map<Stmt, Integer> Stmt2IDMap, 
	                            Map<Integer, Stmt> ID2StmpMap, 
	                            Unit CurUnit, List<Integer> BranchInfo) throws IOException
	{
		String SaIR = "";
		Stmt CurSt = (Stmt)CurUnit;
		
		if((CurSt instanceof IfStmt) && GenIfStmtBv ((IfStmt) CurSt, BranchInfo) == true)
		{
			SaIR += "CMP:";
		}
		else if(CurSt instanceof SwitchStmt)
		{
			GenSwitchStmtBv (CurSt, BranchInfo);	
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
		Map<Block, Integer> VisitedBb = new HashMap<>();
        
        List<Integer> BranchInfo = new ArrayList<Integer>();
        BranchInfo.add (0, 0);
        BranchInfo.add (1, 0);
		
		SootMethod CurMethod = body.getMethod();		
		//if (IsInBlackList (CurMethod.getDeclaration()))
		//{
		//	return;
		//}
		
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
			units.insertBefore(dynStmt, Hb.getHead());
		}
        
		/* init block-id */
		int MaxBID = InitBlockMap (Block2ID, BG.getBlocks());
		
	    /* init CFG and compute dominance */	
		List<Block> wfQueue = new ArrayList<Block>();	
		wfQueue.add(Heads.get(0));
		VisitedBb.put(Heads.get(0), 1);
		
		int CFGHd = PCGuidance.pcgCFGAlloct(Block2ID.get(Heads.get(0)));		
		while (!wfQueue.isEmpty())
		{
			Block CurB= wfQueue.get(0);
			wfQueue.remove(0);
			
			int CurBId = Block2ID.get(CurB);
			
			/* for each block, translate the statement to SA-IR */
			Debug.DebugPrint ("[SA-IR] Block -> " + CurBId);
			for (Unit CurUnit : CurB)
			{
				try {
					String SaIR = GetSaIR (Stmt2IDMap, ID2StmtMap, CurUnit, BranchInfo);
					Debug.DebugPrint ("\t statement ->  " + CurUnit.toString() + " -> SAIR: " + SaIR + "\r\n");
					PCGuidance.pcgInsertIR(CFGHd, CurBId, SaIR);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			
			List<Block> Succs = CurB.getSuccs();
			for (Block su: Succs)
			{
				if (VisitedBb.get(su) == null)
				{
					wfQueue.add (su);
					VisitedBb.put (su, 1);
				}
				PCGuidance.pcgCFGEdge(CFGHd, CurBId, Block2ID.get(su));
			}		
		}	
		PCGuidance.pcgBuild(CFGHd);
		
		/* start to instrument with PCG */
		Chain units = body.getUnits();
		for (Block CurB : Block2ID.keySet())
		{
			Debug.DebugPrint ("[PCG]Block -> " + Block2ID.get(CurB).toString());
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
					Debug.DebugPrint ("\t[PCG]Not contains key -> " + StmtID);
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
				Debug.DebugPrint ("\tInstrument before statement -> " + InstrmedStmt.toString());
			}			
		}
		
		/* start to instrument with SAI */
		int[] AllSAIStmtIDs = PCGuidance.pcgGetAllSAIStmtIDs(CFGHd);
		for (int ix = 0, Size= AllSAIStmtIDs.length; ix < Size; ix++)
		{
		    int StmtID = AllSAIStmtIDs [ix];
		    if (ID2StmtMap.containsKey(StmtID) == false)
		    {
		    	Debug.DebugPrint ("\t[SAI]Not contains key -> " + StmtID);
		    	continue;
		    }

		    Unit InstrmedStmt = ID2StmtMap.get(StmtID);
		    InstrumentSAI (units, 0, InstrmedStmt);
		}
		
		PCGuidance.pcgCFGDel(CFGHd);
        
        /* insert exit function */
		InsertExitStmt (body, isMainMethod);
        DumpCmpStat (CurMethod.getName (), BranchInfo.get (0), BranchInfo.get (1));
        System.out.println ("@@@ instrumenting method : " + CurMethod.getSignature() + ", BlockId to " + Integer.toString (MaxBID));
	}
}
