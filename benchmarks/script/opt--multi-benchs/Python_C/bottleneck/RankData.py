import sys
import atheris

import numpy as np

with atheris.instrument_imports(key="bottleneck"):
    import bottleneck as bn

def TestOneInput(data):  
    fdp = atheris.FuzzedDataProvider(data)
    original = fdp.ConsumeInt(10)
    a = np.array([1, 2, 3, 4, original])
    bn.rankdata(a)
    
if __name__ == '__main__':
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

        