import sys
import os
import random
import atheris

with atheris.instrument_imports(key="libsmbios"):
    import libsmbios_c.memory as Mem

pageunit = 8192

seed_path = "seed.bin"    
def WriteSeed (data):
    F = open (seed_path, "wb")
    F.write (data)
    F.close ()
    return seed_path

@atheris.instrument_func  
def RunTest (data):
    Tf = WriteSeed (data)
    try:
        pagenum = int (len (data)/pageunit)
        if pagenum == 0:
            return
        
        Tf = Tf.encode('utf-8')
        memObj = Mem.MemoryAccess(Mem.MEMORY_GET_NEW | Mem.MEMORY_UNIT_TEST_MODE, Tf)
        
        Offset = 1024
        for i in range(Offset):
            memObj.write(chr(ord("a") + i).encode('utf-8'), i)

        for i in range(pagenum):
            memObj.write(chr(ord("0") + i).encode('utf-8') * 128, pageunit * i)
     
        memObj.search("".encode("utf-8"), 0, 1024, 8);
        
        if pagenum > 2:  
            index = random.randint (1, pagenum-1)
            memObj.search("00000000000000000000000000000".encode("utf-8"), 0, pageunit*index, 1);
        else:
            index = random.randint (0, pagenum)
            memObj.search("00000000000000000000000000000".encode("utf-8"), 2048, pageunit*index, 1);
           
        if pagenum == 1:
            offset = random.randint (0, 2048)
            size   = random.randint (0, 4096)
            memObj.read(offset, size)
        else:    
            offset = random.randint (0, pagenum) * pageunit
            size = random.randint (0, pageunit)
            memObj.read(offset, size)

        del(memObj)
        
    except Exception as e:
        print (e)
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)

if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()

