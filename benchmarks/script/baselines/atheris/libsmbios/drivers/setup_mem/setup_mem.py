import sys
import libsmbios_c.memory as Mem
import pyprob

pyprob.Setup('py_summary.xml', 'setup_mem.py')

pageunit = 4096

def page_num (Tf):
    Index = Tf.find ('-')
    pn = int (Tf[Index+1:]) + 1
    return pn

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

        memObj.close_hint(1)
        del(memObj)
        
    except Exception as e:
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)

