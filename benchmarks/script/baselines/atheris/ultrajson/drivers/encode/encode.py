import sys
import atheris

with atheris.instrument_imports():
    import ujson

@atheris.instrument_func    
def RunTest (InputData):
    try:
        enc = ujson.encode(InputData)
        dec = ujson.decode(enc)
        enc = ujson.dumps (InputData)
        dec = ujson.loads(enc)
    except Exception as e:
        print (e)

if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()
