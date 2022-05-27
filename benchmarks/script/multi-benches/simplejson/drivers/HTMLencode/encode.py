import sys
import pyprob
import simplejson as json


pyprob.Setup('py_summary.xml', 'encode.py')

def LoadInput (TxtFile):
    Content = ""
    with open(TxtFile, 'r', encoding='utf-8') as f:
        Content = f.readlines()
    return Content

if __name__ == '__main__':
    try:
        InputData = str(LoadInput (sys.argv[1]))
        
        decoder = json.JSONDecoder()
        encoder = json.JSONEncoderForHTML()
        
        en = encoder.encode (InputData)
        decoder.decode (en)
        
    except Exception as e:
        print ("Exception")
        print (e)
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)
    
