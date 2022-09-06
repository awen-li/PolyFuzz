
import sys
import atheris
from PyDemo import *

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
    try: 
        Input = int (data)
        Value = Trace (Input)
    except Exception as e:
        pass

if __name__ == '__main__':
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

    
    

