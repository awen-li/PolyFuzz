import sys
import atheris

with atheris.instrument_imports():
    from msgpack import fallback, _cmsgpack

@atheris.instrument_func    
def RunTest (bytes):
    try: 
        to = [bytes, {"Tobj":[bytes]}, [bytes], (bytes, bytes, bytes, bytes, bytes, bytes)]
        #print (to)
        
        fpacker = fallback.Packer()
        for i in range (0, 508):
            to = [fpacker.pack(to)]
   
        packer = _cmsgpack.Packer()
        
        to = to * 10000
        to = packer.pack(to)
        to = fpacker.pack(to)
        
        _cmsgpack.unpackb (to)

    except Exception as e:
        print (e)

if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()
