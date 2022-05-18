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
        bytes = LoadInput (sys.argv[1])
        to = [bytes, {"Tobj":[bytes]}]
        #print (to)
        
        for i in range (0, 508):
            to = [packb(to)]
   
        buf = bytearray(packb(to))
        unpackb(buf)

    except Exception as e:
        print ("Exception --> ", end="")
        print (e)
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)
    
