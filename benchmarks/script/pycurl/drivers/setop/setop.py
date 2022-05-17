import sys
import pyprob
import pycurl

PY3 = sys.version_info[0] > 2

pyprob.Setup('py_summary.xml', 'setop.py')

def LoadInput (fName):
    Content = ""
    with open(fName, 'rb') as F:
        Content = F.read ()
    return Content

#def WriteTest (fName):
#    Content = b"\x01\x01\x01\x01\x01\x01\x05\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
#    with open(fName, 'wb') as F:
#        F.write (Content)
#    return

class TtCurl:
    def __init__(self):
        self.contents = ''
        if PY3:
            self.contents = self.contents.encode('ascii')

    def write_callback(self, buf):
        self.contents = self.contents + buf


t = TtCurl()
c = pycurl.Curl()

OpList = [pycurl.LOW_SPEED_TIME, pycurl.LOW_SPEED_LIMIT, pycurl.CONNECTTIMEOUT, pycurl.FOLLOWLOCATION, pycurl.MAXREDIRS, 
          pycurl.NOSIGNAL, pycurl.RESUME_FROM_LARGE, pycurl.MAX_SEND_SPEED_LARGE, pycurl.MAXREDIRS, 
          pycurl.MAXCONNECTS, pycurl.FRESH_CONNECT, pycurl.CONNECTTIMEOUT, pycurl.HTTP_VERSION, pycurl.FTP_USE_EPSV, 
          pycurl.TIMECONDITION, pycurl.TIMEVALUE]

if __name__ == '__main__':
    try:
        #WriteTest ("tests/test-0")
        Opvals = bytearray (LoadInput (sys.argv[1]))
        OpValLen = len (Opvals)
        #print (OpValLen)
        
        OpListLen = len (OpList)
        if OpListLen > OpValLen:
            OpValLen = OpValLen
        
        c.setopt(c.URL, "https://curl.haxx.se/dev/")
        c.setopt(c.WRITEFUNCTION, t.write_callback)
        
        for OpIndex in range (0, OpListLen):
            c.setopt(OpList[OpIndex], int (Opvals[OpIndex]))
            #print ("[%u]" %OpIndex, end = ": ")
            #print (OpList[OpIndex], end = " ---- ")
            #print (Opvals[OpIndex])

        c.perform()
        c.close()
        
    except Exception as e:
        #print ("Exception")
        #print (e)
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)
    
