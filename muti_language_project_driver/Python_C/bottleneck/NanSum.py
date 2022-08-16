import sys
import atheris

with atheris.instrument_imports(key="bottleneck"):
    import bottleneck as bn

def TestOneInput(data):  
    fdp = atheris.FuzzedDataProvider(data)
    original = fdp.ConsumeInt(10)
    bn.nansum(original)
    
if __name__ == '__main__':
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()
 