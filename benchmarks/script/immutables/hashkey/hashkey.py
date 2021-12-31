
import sys
from immutables.map import Map as PyMap
from immutables._testutils import HashKey

import pyprob


pyprob.Setup('py_summary.xml', 'np_take.py')

def LoadInput (TxtFile):
    Content = ""
    with open(TxtFile, 'r', encoding='latin1') as txfile:
        for line in txfile:
            Content = line.replace("\n", "")
            break
    return Content

if __name__ == '__main__':
    try:
        data = LoadInput (sys.argv[1])
        k1 = HashKey(10, data)
        h = PyMap()
        h.set(k1, data)
    except Exception as e:
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)

