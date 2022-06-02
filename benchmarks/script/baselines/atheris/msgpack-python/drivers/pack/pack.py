import sys
import atheris

with atheris.instrument_imports(key="msgpack"):
    from msgpack import packb, unpackb

@atheris.instrument_func    
def RunTest (bytes):
    try: 
        to = [bytes, {"Tobj":[bytes]}]
        #print (to)
        
        for i in range (0, 508):
            to = [packb(to)]
   
        buf = bytearray(packb(to))
        unpackb(buf)

    except Exception as e:
        print (e)

if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()