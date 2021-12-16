#!/usr/bin/python
# _*_ coding:utf-8 _*_
import os
import re
import ast
from ast import *
import astunparse

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
        self.Callee  = ""
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
        if module[0:4] == "test":
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

    def visit_expr(self, node):
        node = node.value
        self.visit (node)   

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

    def visit_attribute(self, node):
        value = node.value
        if isinstance (value, Name):
            self.Callee += value.id + "." + node.attr
        elif isinstance(value, Attribute):
            self.visit_attribute (value)
            self.Callee += "." + node.attr
        else:
            pass

    def get_args (self, Args):
        Ta = TestApi ()

        for arg in Args:
            if isinstance (arg, Str):
                print (ast.dump (arg))
                Ta.AddArg(arg.s)
            else:
                sArg = astunparse.unparse(arg)
                Ta.AddArg(sArg)
                print ("sArg ===> " + sArg)
        
        return Ta

    def visit_call (self, node):
        Callee = node.func
        if isinstance (Callee, Name):
            if Callee.id == self.ApiName:
                TA = self.get_args (node.args)
                if len (TA.Arg2Value) == 0:
                    return             
                self.TestApi.append (TA)
            else:
                pass
                
        elif isinstance (Callee, Attribute):
            #print (ast.dump (node))
            self.Callee = ""
            self.visit_attribute (Callee)
            if self.Callee.find (self.ApiName) != -1:
                self.ApiName = self.Callee
                TA = self.get_args (node.args)
                if len (TA.Arg2Value) == 0:
                    return             
                self.TestApi.append (TA)
            else:
                Args = node.args
                for arg in Args:
                    self.visit (arg)
        else:
            Args = node.args
            for arg in Args:
                self.visit (arg)