#!/usr/bin/python

from DemoAdd import DemoAdd

import sys
import pyprob

pyprob.Setup('py_summary.xml', 'Demo.py')
 
def DemoTr (ValList):
    Res = 0
    Da  = DemoAdd (100)
    for val in ValList:
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
        ValList = eval (LoadInput (sys.argv[1]))
        Res = DemoTr (ValList)
    except Exception as e:
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)

