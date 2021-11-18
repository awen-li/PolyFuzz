#!/usr/bin/python
# _*_ coding:utf-8 _*_
import os
import re
import ast
from ast import *

class FuncDef ():
    def __init__(self, Cls, FName, Fid, FormalParas):
        self.Cls   = Cls
        self.Id    = Fid
        self.Name  = FName
        self.Paras = FormalParas

    def View (self):
        print ("FuncDef: Id = ", self.Id, " Name = ", self.Name, " Paras = ", self.Paras)

class ASTWalk(NodeVisitor):
    def __init__(self):
        self.FuncDef   = {}
        self.FId = 1
    
    def visit(self, node):
        """Visit a node."""
        if node is None:
            return
        method = 'visit_' + node.__class__.__name__.lower()
        visitor = getattr(self, method, self.generic_visit)
        return visitor(node)

    def _GetArgs (self, Stmt):
        ArgList = []
        Args = Stmt.args.args
        for arg in Args:
            if Stmt.name == "__init__" and arg.arg == "self":
                continue
            ArgList.append (arg.arg)
        return ArgList

    
    def _GetFuncDef (self, Stmt, ClfName=None):
        Fid = self.FId
        self.FId += 1
        
        ArgList = self._GetArgs (Stmt)
        if ClfName == None:
            if 'self' in ArgList:
                return None
            return FuncDef ("", Stmt.name, Fid, ArgList)
        else:
            FullName = ClfName + "." + Stmt.name
            return FuncDef (ClfName, FullName, Fid, ArgList)

    def visit_functiondef(self, node, ClfName=None):
        FuncName = node.name
        if FuncName[0:2] == "__":
            return
        
        Def = self._GetFuncDef (node, ClfName)
        if Def != None:
            self.FuncDef [Def.Name] = Def

        print ("Parse function ===> ", Def.Name)
        Body = node.body
        for Stmt in Body:
            self.visit (Stmt)

        return

    def visit_classdef(self, node):
        print ("Parse class ===> ", node.name)
        Body = node.body
        for Fdef in Body:
            if not isinstance (Fdef, FunctionDef):
                continue
            
            Def = self._GetFuncDef (Fdef, node.name)
            self.FuncDef[Def.Name]  = Def
            
            self.visit_functiondef (Fdef, node.name)
        return

    def visit_if(self, node):
        print (ast.dump (node))
        return

    