import sys
import atheris
import tempfile

with atheris.instrument_imports(key="pycurl"):
    import pycurl
          
@atheris.instrument_func    
def RunTest (InputData):

    fdp = atheris.FuzzedDataProvider(InputData)
    original = fdp.ConsumeString(sys.maxsize)

    try:
        
        c = pycurl.Curl()
        c.setopt(pycurl.OPT_CERTINFO, 1)
        c.setopt(pycurl.URL, "localhost")
        c.setopt(pycurl.FOLLOWLOCATION, 1)
        c.perform()
        c.close()

    except Exception as e:
        pass
        

if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()
