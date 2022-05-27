import sys
import pyprob
import ujson


pyprob.Setup('py_summary.xml', 'encode.py')

def LoadInput (TxtFile):
    Content = ""
    with open(TxtFile, 'r', encoding='latin1') as txfile:
        for line in txfile:
            Content = line.replace("\n", "")
            break
    return Content

if __name__ == '__main__':
    try:
        InputData = eval (LoadInput (sys.argv[1]))
        enc = ujson.encode(InputData)
        dec = ujson.decode(enc)
        enc = ujson.dumps (InputData)
        dec = ujson.loads(enc)
    except Exception as e:
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)
    
