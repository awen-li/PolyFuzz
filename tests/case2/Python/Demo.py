#!/usr/bin/python
import sys
import pyprob
from PyDemo import *

pyprob.Setup('py_summary.xml')

class Demo ():
    def __init__ (self, value):
        if value < 0:
            self.v = 0 - value
        else:
            self.v = value
    
def Trace (val):
    D = Demo (val)
    PwdInfo (D.v)
    Hint = D.v % 8
    if Hint == 1:
        return (Hint+2)
    elif Hint == 2:
        return (Hint*2)
    else:
        return (8 / Hint)

def ParseText (TxtFile):
    Content = ""
    with open(TxtFile, 'r', encoding='latin1') as txfile:
        for line in txfile:
            Content = line.replace("\n", "")
            break
    return Content
  
def main (Test):
    Str = ParseText (Test)
    if Str.isdigit() == False:
    	exit (0)
    Input = int (Str)
    Value = Trace (Input)
  
if __name__ == '__main__':
    try:
        main (sys.argv[1])
    except Exception as e:
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)


    
    

