import sys
import libsmbios_c.memory as Mem
    
if __name__ == '__main__':
    try:
        Tf = sys.argv[1]
   
        Tf = Tf.encode('utf-8')
        memObj = Mem.MemoryAccess(Mem.MEMORY_GET_NEW | Mem.MEMORY_UNIT_TEST_MODE, Tf)
        
        Offset = 1024
        for i in range(Offset):
            memObj.write(chr(ord("a") + i).encode('utf-8'), i)

        del(memObj)
        
    except Exception as e:
        print (e)
