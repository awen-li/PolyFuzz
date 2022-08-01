from ast import Try
import sys
import atheris
from io import BytesIO

with atheris.instrument_imports(key="msgpack"):
    import msgpack

@atheris.instrument_func    
def RunTest (InputData):
    try:
        fdp = atheris.FuzzedDataProvider(InputData)
        original = fdp.ConsumeInt(8)
        buf = BytesIO()
        buf.write(msgpack.packb(original, use_bin_type=True))
        buf.seek(0)
        msgpack.Unpacker(buf, raw=False)
    except:
        pass
    

if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()  