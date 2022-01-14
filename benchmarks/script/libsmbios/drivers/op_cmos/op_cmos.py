import sys
import libsmbios_c.cmos as Cmos
import ctypes
import pyprob

pyprob.Setup('py_summary.xml', 'op_cmos.py')

pageunit = 4096

def _test_cb(cmosObj, do_update, userdata):
    i = ctypes.cast(userdata, ctypes.POINTER(ctypes.c_uint16))
    i[0] = i[0] + 1
    return 1

def page_num (Tf):
    Index = Tf.find ('-')
    pn = int (Tf[Index+1:]) + 1
    return pn

if __name__ == '__main__':
    try:
        Tf = sys.argv[1]
        pagenum = page_num (Tf)
        
        Tf = Tf.encode('utf-8')
        cmosObj = Cmos.CmosAccess(Cmos.CMOS_GET_NEW | Cmos.CMOS_UNIT_TEST_MODE, Tf)
        
        Offset = pagenum * (1024)
        int = ctypes.c_uint16(0)
        cmosObj.registerCallback(_test_cb, ctypes.pointer(int), None)
        
        print ("Offset = %d" %Offset)
        for i in range(Offset):
            if i%4 != 0:
                continue
            b = cmosObj.readByte(0, 0, i)
            cmosObj.writeByte( b + ord('A') - ord('a'), 0, 0, i)

        del(cmosObj)
        
    except Exception as e:
        print (e)
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)

