import sys
import atheris

with atheris.instrument_imports(key="pycurl"):
    import pycurl

PY3 = sys.version_info[0] > 2

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
          
@atheris.instrument_func    
def RunTest (InputData):
    try:
        Opvals = bytearray (InputData)
        OpValLen = len (Opvals)
        
        OpListLen = len (OpList)
        if OpListLen > OpValLen:
            OpValLen = OpValLen
        
        c.setopt(c.URL, "https://curl.haxx.se/dev/")
        c.setopt(c.WRITEFUNCTION, t.write_callback)
        
        for OpIndex in range (0, OpListLen):
            c.setopt(OpList[OpIndex], int (Opvals[OpIndex]))

        c.perform()
        c.close()
        
    except Exception as e:
        print (e)
        

if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()

