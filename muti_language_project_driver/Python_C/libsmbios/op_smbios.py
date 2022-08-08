import sys
import atheris

with atheris.instrument_imports(key="libsmbios"):
    import libsmbios_c.smbios as Smbios
    
@atheris.instrument_func  
def RunTest (data):
        
    fdp = atheris.FuzzedDataProvider(data)
    Tf = fdp.ConsumeString(sys.maxsize)
    
    try:
        Tf = Tf.encode('utf-8')
        tableObj = Smbios.SmbiosTable(Smbios.SMBIOS_GET_SINGLETON | Smbios.SMBIOS_UNIT_TEST_MODE, Tf)
        
        biosStruct = tableObj.getStructureByType(0)
        for i in [1,2,3,4,5,6,7,8,9]:
            biosStruct.getString(i)

        del(tableObj)
        
    except Exception as e:
        pass

if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()
