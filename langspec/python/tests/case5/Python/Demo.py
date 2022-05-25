#!/usr/bin/python
import sys
import pyprob
from PyDemo import *

pyprob.Setup('py_summary.xml', 'Demo.py')

class PwManage:
    def __init__ (self, Key):
        self.Key = Key
    
    def Retrieve (self, Key):
        return "RetrievePwd";
       
    def getPwd (self):
        if self.Key > 9999 and self.Key < 11000:
	        return PwdInfo (self.Key)
        else:
	        return self.Retrieve (self.Key)

def ParseText (TxtFile):
    Content = ""
    with open(TxtFile, 'r', encoding='latin1') as txfile:
        for line in txfile:
            Content = line.replace("\n", "")
            break
    return Content
  
def main (Test):
    Str = ParseText (Test)
    Key = int (Str)
    Pwm = PwManage (Key)
    PW  = Pwm.getPwd ();
  
if __name__ == '__main__':
    try:
        main (sys.argv[1])
    except Exception as e:
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)


    
    

