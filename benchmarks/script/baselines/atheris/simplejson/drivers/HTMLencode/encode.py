import sys
import atheris

with atheris.instrument_imports():
    import simplejson as json

@atheris.instrument_func    
def RunTest (InputData):
    try:
        decoder = json.JSONDecoder()
        encoder = json.JSONEncoderForHTML()
        
        en = encoder.encode (InputData)
        decoder.decode (en)
        
    except Exception as e:
        print (e)
        

if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()