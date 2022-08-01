import sys
import os
import ctypes
import atheris

with atheris.instrument_imports(key="libsmbios"):
    import libsmbios_c.cmos as Cmos

pageunit = 4096

def _test_cb(cmosObj, do_update, userdata):
    i = ctypes.cast(userdata, ctypes.POINTER(ctypes.c_uint16))
    i[0] = i[0] + 1
    return 1

@atheris.instrument_func  
def RunTest (InputData):

    fdp = atheris.FuzzedDataProvider(InputData)
    Tf = fdp.ConsumeString(sys.maxsize)

    try:
        pagenum = int (len (InputData)/pageunit)
        
        Tf = Tf.encode('utf-8')
        cmosObj = Cmos.CmosAccess(Cmos.CMOS_GET_NEW | Cmos.CMOS_UNIT_TEST_MODE, Tf)
        
        Offset = pagenum * (1024)
        c_int = ctypes.c_uint16(0)
        cmosObj.registerCallback(_test_cb, ctypes.pointer(c_int), None)
        
        for i in range(Offset):
            if i%4 != 0:
                continue
            b = cmosObj.readByte(0, 0, i)
            cmosObj.writeByte( b + ord('A') - ord('a'), 0, 0, i)

        del(cmosObj)
        
    except Exception as e:
        pass

if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()

