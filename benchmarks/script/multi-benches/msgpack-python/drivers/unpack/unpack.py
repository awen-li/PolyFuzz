import sys
import pyprob
import io
import msgpack

pyprob.Setup('py_summary.xml', 'unpack.py')

binarydata = bytes(bytearray(range(256)))


def LoadInput (FName):
    Content = ""
    with open(FName, 'rb') as f:
        Content = f.read()
    return Content

if __name__ == '__main__':
    try: 
        Values = bytearray (LoadInput (sys.argv[1]))
        Length = len (Values)
        if Length < 4:
            exit (0)
 
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
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)
    
