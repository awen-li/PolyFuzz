#!/usr/bin/python

import os
from ast import parse
from .AstTestArgs import AstTestArgs

TestDir = "tests"


def PrepareDir (ApiName):
    # driver dir
    if not os.path.exists (ApiName):
        os.makedirs(ApiName)

        # tests
        os.makedirs(ApiName + "/" + TestDir)
    
    os.chdir (ApiName)
    return

def GenTestArgs (PyFile, ApiName, Exp=False):

    with open(PyFile) as PyF:
        print ("#visit " + PyFile)
        Ast = parse(PyF.read(), PyFile, 'exec')
        Visitor = AstTestArgs(ApiName)
        Visitor.visit(Ast)

        PrepareDir (ApiName)   

        # Gen tests
        TestNo = 0
        for TtApi in Visitor.TestApi:
            TestFile = TestDir + "/test-" + str (TestNo)
            with open(TestFile, 'w') as TF:
                for No, Arg in TtApi.Arg2Value.items ():
                    TF.write(Arg)
                    break
            TestNo += 1

        # Gen driver
        CurApiName = Visitor.ApiName
        CurInport  = "".join (Visitor.Imports)

        Eval = ""
        if Exp == True:
            Eval = "eval"

        PyScript   = ApiName+".py"
        PyTemplate = (
                    f"{CurInport}\n"
                    "import sys\n"
                    "import pyprob\n"
                    "\n"
                    "\n"
                    f"pyprob.Setup('py_summary.xml', \'{PyScript}\')\n"
                    "\n"
                    "def LoadInput (TxtFile):\n"
                    "    Content = \"\"\n"
                    "    with open(TxtFile, 'r', encoding='latin1') as txfile:\n"
                    "        for line in txfile:\n"
                    "            Content = line.replace(\"\\n\", \"\")\n"
                    "            break\n"
                    "    return Content\n"
                    "\n"
                    "if __name__ == '__main__':\n"
                    "    try:\n"
                    f"        data = {Eval}(LoadInput (sys.argv[1]))\n"
                    f"        res = {CurApiName}(data)\n"
                    "    except Exception as e:\n"
                    "        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)\n"
                    )

        Driver = open (PyScript, "w")
        print (PyTemplate, file=Driver)
        Driver.close ()

        ShTemplate = (
                    "export AFL_SKIP_BIN_CHECK=1\n\n"
                    "if [ ! -d \"fuzz\" ]; then\n"
                    "   mkdir -p fuzz/in\n"
                    f"   cp ./{TestDir}/* fuzz/in/\n"
                    "fi\n\n"
                    "cd fuzz\n"
                    "afl-system-config\n\n"
                    "#pilot fuzzing: max path length\n"
                    "export AFL_BB_NUM=65535\n\n"
                    "#timeout threshold\n"
                    "export AFL_FORKSRV_INIT_TMOUT=2\n\n"
                    "#enable debug for child process\n"
                    "#export AFL_DEBUG_CHILD=1\n\n"
                    "#enable crash exit code\n" 
                    "export AFL_CRASH_EXITCODE=100\n\n"
                    "cp ../../py_summary.xml ./\n"
                    f"afl-fuzz $1 $2 -i in/ -o out -m none -d -- python ../{PyScript}  @@\n"
                    )
        Fuzzer = open ("run-fuzzer.sh", "w")
        print (ShTemplate, file=Fuzzer)
        Fuzzer.close ()