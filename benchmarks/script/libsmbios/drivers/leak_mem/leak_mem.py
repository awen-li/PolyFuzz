import sys
import libsmbios_c.memory as Mem
import libsmbios_c.cmos as Cmos
import pyprob

pyprob.Setup('py_summary.xml', 'leak_mem.py')

def LoadInput (TxtFile):
    Content = ""
    with open(TxtFile, 'r', encoding='latin1') as txfile:
        for line in txfile:
            Content = line.replace("\n", "")
            break
    return Content

if __name__ == '__main__':
    try:
        LoopNum = int (LoadInput (sys.argv[1]))
        for i in range(LoopNum):
            mObj = Mem.MemoryAccess(Mem.MEMORY_GET_NEW | Mem.MEMORY_UNIT_TEST_MODE, "/dev/null")
            cObj = Cmos.CmosAccess(Cmos.CMOS_GET_NEW | Cmos.CMOS_UNIT_TEST_MODE, "/dev/null")
            del(mObj)
            del(cObj)
        
    except Exception as e:
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)

