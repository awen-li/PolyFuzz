#!/usr/bin/python

import os
import sys, getopt
import marshal
from ast import parse
from .AstWalk import ASTWalk
from os.path import join, abspath, splitext, realpath
from xml.dom.minidom import Document
import pickle

def IsInExpList (py, PyFile, ExpList):
    if ExpList == None:
        return False
    if py in ExpList:
        return True
    for exp in ExpList:
        Hd = exp[0:2]
        if Hd != "-D":
            continue
        if PyFile.find (exp[2:]) != -1:
            return True
    return False

def _AddChildNode (Doc, Parent, Child, Value=None):
    CNode = Doc.createElement(Child)
    Parent.appendChild(CNode)
    if Value != None:
        Val = Doc.createTextNode(Value)
        CNode.appendChild(Val)
    return CNode
    

def GenBrVal (PyDir, ExpList=None):
    doc  = Document()  
    Root = _AddChildNode (doc, doc, "branch_variables")

    SrcApiList = {}
    FuncDefList = {}
    
    PyDirs = os.walk(PyDir) 
    for Path, Dirs, Pys in PyDirs:
        for py in Pys:
            _, Ext = os.path.splitext(py)
            if Ext != ".py":
                continue
         
            PyFile = os.path.join(Path, py)
            if IsInExpList (py, PyFile, ExpList) == True:
                continue  

            Prefix = py[0:5]
            if Prefix == "test_":
                continue
            
            with open(PyFile) as PyF:
                Ast = parse(PyF.read(), PyFile, 'exec')
                Visitor= ASTWalk()
                Visitor.visit(Ast)
 
                # function definition retrieve
                FuncDef = Visitor.FuncDef
                for FuncName, FDef in FuncDef.items ():
                    FDef.Id = len (FuncDefList)+2
                    FuncDefList[FuncName] = FDef

    for FuncName, Def in FuncDefList.items ():
        BrVals = list(set (Def.BrVal))
        
        FuncNode = _AddChildNode (doc, Root, "function")
        FuncNode.setAttribute ("name", FuncName)
        FuncNode.setAttribute ("brval", " ".join(BrVals))

    # write to xml
    f = open(PyDir+"branch_variables.xml", "w")
    f.write(doc.toprettyxml(indent="  "))
    f.close()

