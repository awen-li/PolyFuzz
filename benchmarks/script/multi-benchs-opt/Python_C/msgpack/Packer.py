import sys
import atheris
from io import BytesIO
import pyprob

with atheris.instrument_imports(key="msgpack"):
    import msgpack

#pyprob.Setup('py_summary.xml', 'pack.py')

def LoadInput (FName):
    Content = ""
    with open(FName, 'rb') as f:
        Content = f.read()
    return Content

@atheris.instrument_func    
def RunTest (bytes):
    try: 
        to = [bytes, {"Tobj":[bytes]}, [bytes], (bytes, bytes, bytes, bytes, bytes, bytes)]
        to = [packb(to)]
        buf = bytearray(packb(to))

    except Exception as e:
        pass

if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()  