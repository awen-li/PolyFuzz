import sys
import pyprob
from msgpack import fallback, _cmsgpack

pyprob.Setup('py_summary.xml', 'cmspack.py')

def LoadInput (FName):
    Content = ""
    with open(FName, 'rb') as f:
        Content = f.read()
    return Content

if __name__ == '__main__':
    try: 
        bytes = LoadInput (sys.argv[1])
        to = [bytes, {"Tobj":[bytes]}, [bytes], (bytes, bytes, bytes, bytes, bytes, bytes)]
        #print (to)
        
        fpacker = fallback.Packer()
        for i in range (0, 508):
            to = [fpacker.pack(to)]
   
        packer = _cmsgpack.Packer()
        
        to = to * 10000
        to = packer.pack(to)
        to = fpacker.pack(to)
        
        _cmsgpack.unpackb (to)

    except Exception as e:
        print ("Exception --> ", end="")
        print (e)
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)
    
