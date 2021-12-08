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
    Root = _AddChildNode (doc, doc, "py_summary")

    SrcApiList = {}
    FuncDefList = {}
    BranchNum = 0
    
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
                print ("#visit " + PyFile)
                Ast = parse(PyF.read(), PyFile, 'exec')
                Visitor= ASTWalk()
                Visitor.visit(Ast)

                BranchNum += Visitor.BranchNum*2
 
                # function definition retrieve
                FuncDef = Visitor.FuncDef

                # add childnode file
                FileNode = _AddChildNode (doc, Root, "file")
                FileNode.setAttribute ("name", py)

                for FuncName, Def in FuncDef.items ():
                    BrVals = list(set (Def.BrVal))
                    
                    FuncNode = _AddChildNode (doc, FileNode, "function")
                    FuncNode.setAttribute ("class", Def.Cls)
                    FuncNode.setAttribute ("name",  FuncName)
                    FuncNode.setAttribute ("brval", " ".join(BrVals))
                    FuncNode.setAttribute ("bbs", " ".join(Def.BBNo))

    Root.setAttribute ("branchs", str(BranchNum+4))
    # write to xml
    f = open(PyDir+"py_summary.xml", "w")
    f.write(doc.toprettyxml(indent="  "))
    f.close()

