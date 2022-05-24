#!/usr/bin/python

from DemoAdd import DemoAdd

import sys
import pyprob

pyprob.Setup('py_summary.xml', 'Demo.py')
 
def DemoTr (ValDict):
    Res = 0
    Da  = DemoAdd (100)
    for key, val in ValDict.items():
        Res += Da.Add (val)
    return Res

def LoadInput (TxtFile):
    Content = ""
    with open(TxtFile, 'r', encoding='latin1') as txfile:
        for line in txfile:
            Content = line.replace("\n", "")
            break
    return Content

if __name__ == '__main__':
    try:
        ValDict = eval (LoadInput (sys.argv[1]))
        Res = DemoTr (ValDict)
    except Exception as e:
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)

