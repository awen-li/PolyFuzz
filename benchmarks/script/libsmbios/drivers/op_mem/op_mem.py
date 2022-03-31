import sys
import os
import random
import libsmbios_c.memory as Mem
import pyprob

pyprob.Setup('py_summary.xml', 'setup_mem.py')

pageunit = 4096

def page_num (Tf):
    fsize = os.path.getsize(Tf)
    return int (fsize/pageunit)

if __name__ == '__main__':
    try:
        Tf = sys.argv[1]
        pagenum = page_num (Tf)
        
        Tf = Tf.encode('utf-8')
        memObj = Mem.MemoryAccess(Mem.MEMORY_GET_NEW | Mem.MEMORY_UNIT_TEST_MODE, Tf)
        
        Offset = 1024
        for i in range(Offset):
            memObj.write(chr(ord("a") + i).encode('utf-8'), i)

        for i in range(pagenum):
            memObj.write(chr(ord("0") + i).encode('utf-8') * pageunit, Offset + (pageunit * i))
            
        memObj.search("abc".encode("utf-8"), 0, 4096, 1);
        
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
            size = random.randint (0, pagenum) * pageunit
            memObj.read(offset, size)

        del(memObj)
        
    except Exception as e:
        print (e)
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)

