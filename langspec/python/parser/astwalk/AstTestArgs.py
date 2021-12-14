#!/usr/bin/python
# _*_ coding:utf-8 _*_
import os
import re
import ast
from ast import *

class TestApi ():
    def __init__(self, ):
        self.Arg2Value = {}

    def AddArg (self, Value):
        ArgNo = len (self.Arg2Value)
        self.Arg2Value [ArgNo] = Value

class AstTestArgs(NodeVisitor):
    def __init__(self, ApiName):
        self.TestApi = []
        self.Imports = []
        self.ApiName = ApiName
  
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

    def visit_import(self, node):
        #print (ast.dump (node))
        Import = "import "
        for alias in node.names:
            if alias.name == "unittest":
                continue
            
            Import += alias.name
            if alias.asname != None:
                Import += " as " + alias.asname
            if alias != node.names[-1]:
                Import += ", "
        if (len (Import) <= 8):
            return
        
        Import += "\n"
        self.Imports.append (Import)

    def visit_importfrom(self, node):
        #print (ast.dump (node))
        module = node.module
        if module == "test":
            return
        
        Import = "from " + module + " import "
        for alias in node.names:
            Import += alias.name
            if alias.asname != None:
                Import += " as " + alias.asname
            if alias != node.names[-1]:
                Import += ", "
        Import += "\n"
        self.Imports.append (Import)

    def visit_functiondef(self, node, ClfName=None):
        if self._IsBuiltin (node.name) == True:
            return
        Body = node.body
        for Stmt in Body:
            self.visit (Stmt)       
        return

    def visit_classdef(self, node):
        Body = node.body
        for Fdef in Body:
            if not isinstance (Fdef, FunctionDef):
                continue         
            self.visit_functiondef (Fdef, node.name)
        return

    def visit_call (self, node):
        Callee = node.func
        if isinstance (Callee, Name):
            if Callee.id == self.ApiName:
                Args = node.args
                ArgNo = 0
                Ta = TestApi ()
                for arg in Args:
                    if isinstance (arg, Str):
                        Ta.AddArg(arg.s)
                        print (ast.dump (arg))
                if len (Ta.Arg2Value) != 0:
                    self.TestApi.append (Ta)
        else:
            Args = node.args
            for arg in Args:
                self.visit (arg)