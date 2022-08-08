import sys
import atheris

with atheris.instrument_imports(key="simplejson"):
    import simplejson as json


@atheris.instrument_func    
def RunTest (InputData):

    try:
        encoder = json.JSONEncoderForHTML()
        fdp = atheris.FuzzedDataProvider(InputData)
        original = fdp.ConsumeString(sys.maxsize)
        encoder.encode(original)
        
    except Exception as e:
        pass
        

if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()