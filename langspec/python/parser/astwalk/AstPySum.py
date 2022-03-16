#!/usr/bin/python
# _*_ coding:utf-8 _*_
import os
import re
import ast
from ast import *

class FuncDef ():
    def __init__(self, Cls, FName, Fid, SNo):
        self.Cls   = Cls
        self.Id    = Fid
        self.Sline = 0
        self.Eline = 0
        self.Name  = FName
        self.BrVal = []

        self.BBNo  = []
        if SNo != None:
            self.BBNo.append (str(SNo))

    def AddBrVal (self, Val):
        if Val == 'self':
            return
        self.BrVal.append (Val)

    def AddBB (self, BBno):
        if len (self.BBNo) > 0 and int (self.BBNo[-1]) == BBno:
            return
        
        self.BBNo.append (str(BBno))
        
    def View (self):
        print ("FuncDef: Id = ", self.Id, " Name = ", self.Name, " BrVals = ", self.BrVal)

class AstPySum(NodeVisitor):
    def __init__(self):
        self.FuncDef   = {}
        self.FId = 1
        self.IfTest  = False
        self.CurFunc = None
        self.CurLine = 0
        self.BranchNum = 0

        self.BrOps = None
        self.BrCmptors = None

    def InsertBB (self, BB):
        if self.CurFunc == None:
            return

        self.CurFunc.AddBB(BB)
  
    def visit(self, node):
        """Visit a node."""
        if node is None:
            return
        method = 'visit_' + node.__class__.__name__.lower()
        visitor = getattr(self, method, self.generic_visit)
        if self.CurFunc != None and hasattr (node, 'lineno'):
            self.CurLine = node.lineno
        return visitor(node)

    def _IsBuiltin (self, FuncName):
        if FuncName[0:2] == "__" and FuncName != "__init__":
            return True
        else:
            return False

    def _GetFuncId (self):
        Fid = self.FId
        self.FId += 1
        return Fid 
    
    def _GetFuncDef (self, Stmt, ClfName=None):
        Fid = self._GetFuncId ()

        if ClfName == None:
            return FuncDef ("", Stmt.name, Fid, Stmt.lineno)
        else:
            #FullName = ClfName + "." + Stmt.name
            return FuncDef (ClfName, Stmt.name, Fid, Stmt.lineno)

    def GetOpCode (self, Op):
        if isinstance (Op, Eq):
            return 32
        elif isinstance (Op, NotEq):
            return 33
        elif isinstance (Op, Lt):
            return 36
        elif isinstance (Op, LtE):
            return 37
        elif isinstance (Op, Gt):
            return 34
        elif isinstance (Op, GtE):
            return 35
        elif isinstance (Op, Is):
            return 32
        elif isinstance (Op, IsNot):
            return 33
        elif isinstance (Op, In):
            return 32
        elif isinstance (Op, NotIn):
            return 33
        else:
            return 0

    # Key:CMP:PREDICT:Value
    def GenBrVars (self, Var):
        if self.BrOps == None or self.BrCmptors == None:
            return

        Predict = self.GetOpCode (self.BrOps[0]);
        if Predict == 0:
            return
        
        Key = id(Var)
        f = open("branch_vars.bv", "w")
        f.write("111")
        f.close()
        

    def visit_name (self, node):
        if self.IfTest == True and self.CurFunc != None: 
            self.CurFunc.AddBrVal (node.id)
            self.GenBrVars (node.id)
            print ("====> visit variable name: " + self.CurFunc.Name + " --- " + node.id)
        return node.id

    
    def visit_functiondef(self, node, ClfName=None):
        if self._IsBuiltin (node.name) == True:
            return

        print ("##### visit-start %s : %d"  %(node.name, node.lineno))
        Def = self._GetFuncDef (node, ClfName)
        Def.Sline = node.lineno

        Key = Def.Name + str (Def.Sline)
        self.FuncDef [Key] = Def

        self.CurFunc = Def
        Body = node.body
        for Stmt in Body:
            self.visit (Stmt)
            LS = Stmt

        print ("##### visit-end %s : %d \n"  %(node.name, self.CurLine))
        Def.Eline = self.CurLine
        self.CurFunc = None
        self.CurLine = 0
        return

    def visit_classdef(self, node):
        Body = node.body
        for Fdef in Body:
            if not isinstance (Fdef, FunctionDef):
                continue
            
            self.visit_functiondef (Fdef, node.name)
        return

    def visit_boolop(self, node):
        Values = node.values
        for value in Values:
            self.visit(value)

    def visit_call (self, node):
        pass

    def visit_for (self, node):
        print ("#line-no for: %d" %node.lineno)
        self.InsertBB (node.lineno)
        self.BranchNum += 1
        for s in node.body:
            self.visit(s)

    def visit_while (self, node):
        print ("#line-no while: %d" %node.lineno)
        self.InsertBB (node.lineno)
        self.BranchNum += 1
        for s in node.body:
            self.visit(s)

    def visit_with(self, node):
        for s in node.body:
            self.visit(s)

    def visit_try(self, node):
        for s in node.body:
            self.visit(s)

        for s in node.orelse:
            self.visit(s)

        for s in node.finalbody:
            self.visit(s)

    def HasConstInt (self, Cmptors):
        for Cmp in Cmptors:
            if not isinstance (Cmp, Constant):
                continue
            if not isinstance (Cmp.value, int):
                continue
            return True
        return False

    def ParseBranch (self, Test):
        if self.HasConstInt (Test.comparators) == False:
            return

        self.IfTest = True
        
        self.BrOps  = Test.ops
        self.BrCmptors = Test.comparators  
        self.BranchNum += 1
        self.visit(Test)
        
        self.IfTest = False

    def visit_if(self, node):
        print (ast.dump (node))
        print ("#line-no if: %d" %node.lineno)
        self.InsertBB (node.lineno)
        
        # check test
        self.ParseBranch (node.test);

        # continue to body
        for s in node.body:
            self.visit(s)

        # continue to else
        for s in node.orelse:
            print ("#line-no else: %d" %s.lineno)
            self.InsertBB (s.lineno)
            self.visit(s)
            
        return

    