
package JCovPCG;

import java.util.Iterator;
import java.util.Map;

import soot.Body;
import soot.BodyTransformer;
import soot.Local;
import soot.RefType;
import soot.Scene;
import soot.SootMethod;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.Jimple;
import soot.jimple.Stmt;
import soot.jimple.StringConstant;
import soot.util.Chain;


public class CovPCG extends BodyTransformer {

	@Override
	protected void internalTransform(Body body, String phaseName, Map<String, String> options) {
		// TODO Auto-generated method stub
		
	}
}
