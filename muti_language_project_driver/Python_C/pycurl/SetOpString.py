import sys
import atheris

with atheris.instrument_imports(key="pycurl"):
    import pycurl
          
@atheris.instrument_func    
def RunTest (InputData):

    fdp = atheris.FuzzedDataProvider(InputData)
    original = fdp.ConsumeString(sys.maxsize)

    try:
        c = pycurl.Curl()
        c.getinfo_raw(pycurl.INFO_CERTINFO)
        c.setopt_string(10002, original)
        c.close()

    except Exception as e:
        pass
        

if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()