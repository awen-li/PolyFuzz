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
        self.Name  = FName
        self.BrVal = []

        self.BBNo  = []
        if SNo != None:
            self.BBNo.append (str(SNo))

    def AddBrVal (self, Val):
        self.BrVal.append (Val)

    def AddBB (self, BBno):
        self.BBNo.append (str(BBno))
        
    def View (self):
        print ("FuncDef: Id = ", self.Id, " Name = ", self.Name, " BrVals = ", self.BrVal)

class ASTWalk(NodeVisitor):
    def __init__(self):
        self.FuncDef   = {}
        self.FId = 1
        self.IfTest  = False
        self.CurFunc = None
        self.BranchNum = 0

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
        return visitor(node)

    def _IsBuiltin (self, FuncName):
        if FuncName[0:2] == "__":
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

    def visit_name (self, node):
        if self.IfTest == True and self.CurFunc != None:
            FDef = self.FuncDef.get (self.CurFunc.Name)
            FDef.AddBrVal (node.id)
            print ("====> visit variable name: " + self.CurFunc.Name + " --- " + node.id)
        return node.id

    def visit_functiondef(self, node, ClfName=None):
        if self._IsBuiltin (node.name) == True:
            return

        print ("#visit %s : %d"  %(node.name, node.lineno))
        Def = self._GetFuncDef (node, ClfName)
        self.FuncDef [Def.Name] = Def

        self.CurFunc = Def
        Body = node.body
        for Stmt in Body:
            self.visit (Stmt)
        
        self.CurFunc = None
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

    def visit_while (self, node):
        print ("#line-no while: %d" %node.lineno)
        self.InsertBB (node.lineno)
        self.BranchNum += 1

    def visit_if(self, node):
        #print (ast.dump (node))
        print ("#line-no if: %d" %node.lineno)
        self.InsertBB (node.lineno)
        
        # check test
        Test = node.test
        self.IfTest = True
        self.BranchNum += 1
        self.visit(Test)
        self.IfTest = False

        # continue to body
        for s in node.body:
            self.visit(s)

        # continue to else
        for s in node.orelse:
            print ("#line-no else: %d" %s.lineno)
            self.InsertBB (s.lineno)
            self.visit(s)
            
        return

    