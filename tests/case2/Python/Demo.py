#!/usr/bin/python
import sys
import pyprob
from PyDemo import *

Modules = ['Demo.py']
pyprob.Setup(Modules, 'branch_variables.xml')

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
            Content = line
            break
    return Content
    
if __name__ == '__main__':
    Test = sys.argv[1]
    Input = int (ParseText (Test))
    print ("Input = " + str(Input))
    Value = Trace (Input)
    print ("Value = " + str(Value))

