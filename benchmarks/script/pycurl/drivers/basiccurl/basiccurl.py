import sys
import pyprob
import pycurl

PY3 = sys.version_info[0] > 2

pyprob.Setup('py_summary.xml', 'basiccurl.py')

def LoadInput (TxtFile):
    Content = ""
    with open(TxtFile, 'r', encoding='latin1') as txfile:
        for line in txfile:
            Content = line.replace("\n", "")
            break
    return Content


class TtCurl:
    def __init__(self):
        self.contents = ''
        if PY3:
            self.contents = self.contents.encode('ascii')

    def write_callback(self, buf):
        self.contents = self.contents + buf


t = TtCurl()
c = pycurl.Curl()

if __name__ == '__main__':
    try:
        Url = LoadInput (sys.argv[1])
        
        c.setopt(c.URL, Url)
        c.setopt(c.WRITEFUNCTION, t.write_callback)
        c.perform()
        c.close()
        
    except Exception as e:
        print ("Exception")
        print (e)
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)
    
