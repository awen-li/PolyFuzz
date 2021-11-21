#!/usr/bin/python
import os
import pyprob
from DemoAdd import DemoAdd

Modules = ['Demo.py', 'DemoAdd.py']
pyprob.Setup(Modules, 'branch_variables.xml')
 
def DemoTr (Value):
    Var = os.getenv("CASE1")
    if Var == None:
    	Var = '1024'
    
    Var = int (Var)
    if Var == 100:
    	Var = 0
    
    Da = DemoAdd (Var)
    if Da == None or Var < 0:
        return 0
    
    Res = Da.Add (Value)
    return Res


Length = 0
if __name__ == '__main__':
    ResultList = []
    for i in range (1, 8):
    	Result = DemoTr(i)
    	ResultList.append (Result)
    Length = len (ResultList)
    print ("Trace end ---> ", ResultList, " == ", Length)

