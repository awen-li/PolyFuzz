import sys
import atheris

import numpy as np

with atheris.instrument_imports(key="bottleneck"):
    import bottleneck as bn

def TestOneInput(data):  
    fdp = atheris.FuzzedDataProvider(data)
    original = fdp.ConsumeInt(4)
    test_modification("run", original)

def arrays(dtypes, numbers):
    ss = {}
    ss[1] = {"size": 4, "shapes": [(4,numbers)]}
    ss[2] = {"size": 6, "shapes": [(2, 3)]}
    ss[3] = {"size": 6, "shapes": [(1, 2, 3)]}
    rs = np.random.RandomState([1, 2, 3])
    for ndim in ss:
        size = ss[ndim]["size"]
        shapes = ss[ndim]["shapes"]
        for dtype in dtypes:
            a = np.arange(size, dtype=dtype)
            if issubclass(a.dtype.type, np.inexact):
                idx = rs.rand(*a.shape) < 0.2
                a[idx] = np.inf
                idx = rs.rand(*a.shape) < 0.2
                a[idx] = np.nan
                idx = rs.rand(*a.shape) < 0.2
                a[idx] *= -1
            for shape in shapes:
                a = a.reshape(shape)
                yield a

def test_modification(func, numbers):
    """Test that bn.xxx gives the same output as np.xxx."""
    name = func
    if name == "replace":
        return
    msg = "\nInput array modified by %s.\n\n"
    msg += "input array before:\n%s\nafter:\n%s\n"
    for i, a in enumerate(arrays("float64", numbers)):
        axes = list(range(-a.ndim, a.ndim))
        if all(x not in name for x in ["push", "move", "sort", "partition"]):
            axes += [None]

        second_arg = 1
        if "partition" in name:
            second_arg = 0

        for axis in axes:
            with np.errstate(invalid="ignore"):
                a1 = a.copy()
                a2 = a.copy()
                
    
if __name__ == '__main__':
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

        