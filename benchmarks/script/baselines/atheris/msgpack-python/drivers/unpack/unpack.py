import sys
import io
import atheris

with atheris.instrument_imports():
    import msgpack

binarydata = bytes(bytearray(range(256)))


@atheris.instrument_func    
def RunTest (bytes):
    try: 
        Values = bytearray (bytes)
        Length = len (Values)
        if Length < 4:
            return
 
        WriteBytes = Values[0]<<10 | Values[1] << 8 | Values[1]
        ReadBytes  = Values[2]<<10 | Values[3] << 8 | Values[3]
        
        dumpf = io.BytesIO()
        packer = msgpack.Packer()

        for idx in range(WriteBytes):
            dumpf.write(packer.pack(binarydata))

        f = io.BytesIO(dumpf.getvalue())
        dumpf.close()
        msgpack.Unpacker(f, read_size=ReadBytes, use_list=1)

    except Exception as e:
        print ("Exception --> ", end="")
        print (e)

if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()