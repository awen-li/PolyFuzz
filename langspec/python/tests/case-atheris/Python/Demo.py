
import sys
import atheris
from PyDemo import *

with atheris.instrument_imports(key="Demo"):
    import aubio

class Demo ():
    def __init__ (self, value):
        if value < 0:
            self.v = 0 - value
        else:
            self.v = value

@atheris.instrument_func     
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
    
def TestOneInput(data):  
    Input = int (data)
    Value = Trace (Input)
  
if __name__ == '__main__':
    atheris.Setup(sys.argv, main, enable_python_coverage=True)
    atheris.Fuzz()

    
    

