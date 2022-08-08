import sys
import atheris
import json

with atheris.instrument_imports(key="simplejson"):
    import simplejson as json


@atheris.instrument_func    
def RunTest (InputData):

    try:
        decoder = json.JSONDecoder()
        fdp = atheris.FuzzedDataProvider(InputData)
        original = fdp.ConsumeString(sys.maxsize)
        decoder.decode(original)
        
    except Exception as e:
        pass
        

if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()