import sys
import pyprob
from msgpack import packb, unpackb

pyprob.Setup('py_summary.xml', 'pack.py')

def LoadInput (FName):
    Content = ""
    with open(FName, 'rb') as f:
        Content = f.read()
    return Content

if __name__ == '__main__':
    try:
        InputData = LoadInput (sys.argv[1])
        
        buf = bytearray(packb(InputData))
        unpackb(buf)
        
    except Exception as e:
        print ("Exception --> ", end="")
        print (e)
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)
    
