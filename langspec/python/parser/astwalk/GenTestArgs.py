#!/usr/bin/python

import os
from ast import parse
from .AstTestArgs import AstTestArgs


def GenTestArgs (PyFile, ApiName):

    with open(PyFile) as PyF:
        print ("#visit " + PyFile)
        Ast = parse(PyF.read(), PyFile, 'exec')
        Visitor = AstTestArgs(ApiName)
        Visitor.visit(Ast)

        if not os.path.exists (ApiName):
            os.makedirs(ApiName)
        
        TestNo = 0
        for TtApi in Visitor.TestApi:
            TestFile = ApiName + "/test-" + str (TestNo)
            with open(TestFile, 'w') as TF:
                for No, Arg in TtApi.Arg2Value.items ():
                    TF.write(Arg)
                    break
            TestNo += 1


