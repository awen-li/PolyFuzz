import sys
import libsmbios_c.smbios as Smbios
import pyprob

pyprob.Setup('py_summary.xml', 'op_smbios.py')

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
        tableObj = Smbios.SmbiosTable(Smbios.SMBIOS_GET_SINGLETON | Smbios.SMBIOS_UNIT_TEST_MODE, Tf)
        
        biosStruct = tableObj.getStructureByType(0)
        for i in [1,2,3,4,5,6,7,8,9]:
            biosStruct.getString(i)

        del(tableObj)
        
    except Exception as e:
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)

