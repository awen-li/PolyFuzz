
import sys
import yaml.reader
import pyprob

pyprob.Setup('py_summary.xml', 'driver.py')

def LoadBytes (FName):
    bytes = None
    with open (FName, "rb") as bf:
        bytes = bf.read()
    return bytes


if __name__ == "__main__":
    try:
        data = LoadBytes (sys.argv[1])
        if (len (data) < 1):
            exit (0) 
        
        stream = yaml.reader.Reader(data)
        while stream.peek() != u'\0':
            stream.forward()
    except Exception as e:
        #print (e)
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)
