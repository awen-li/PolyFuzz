import sys
import random
import numpy as np
import atheris

with atheris.instrument_imports(key="bottleneck"):
    import bottleneck as bn

def test_memory_leak(number):
    import resource

    arr = np.arange(number).reshape((number, number))

    starting = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    for i in range(1000):
        for axis in [None, 0, 1]:
            bn.nansum(arr, axis=axis)
            bn.nanargmax(arr, axis=axis)
            bn.nanargmin(arr, axis=axis)
            bn.nanmedian(arr, axis=axis)
            bn.nansum(arr, axis=axis)
            bn.nanmean(arr, axis=axis)
            bn.nanmin(arr, axis=axis)
            bn.nanmax(arr, axis=axis)
            bn.nanvar(arr, axis=axis)

    ending = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    diff = ending - starting
    diff * resource.getpagesize()
    
@atheris.instrument_func    
def RunTest (data):
    fdp = atheris.FuzzedDataProvider(data)
    input = fdp.ConsumeInt(10)
    
    try:
        test_memory_leak(input)

 
    except Exception as e:
        pass

if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()