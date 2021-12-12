
import sys
import pymongo
import pyprob


pyprob.Setup('py_summary.xml')

def ParseText (TxtFile):
    Content = ""
    with open(TxtFile, 'r', encoding='latin1') as txfile:
        for line in txfile:
            Content = line.replace("\n", "")
            break
    return Content

if __name__ == '__main__':
    PortStr = ParseText (sys.argv[1])
    Port = int (PortStr)
    try:
        client = pymongo.MongoClient("localhost", Port)
    except Exception as e:
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)