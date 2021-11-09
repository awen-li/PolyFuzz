#!/usr/bin/python
import os
import pyins
from DemoAdd import DemoAdd

pyins.Setup()

Modules = ['Demo.py', 'DemoAdd.py']
pyins.PyInit (Modules)
 
def DemoTr (Value):
    Var = os.getenv("CASE1")
    if Var == None:
    	Var = 1
    if Var == 100:
    	Var = 0
    Var = int (Var)
    Da = DemoAdd (Var)
    Res = Da.Add (Value)
    return Res


if __name__ == '__main__':
    Temp = 8
    Result = DemoTr(Temp)
    print ("trace end", Result)

