import sys
import random
import numpy as np
import bottleneck as bn
import pyprob

pyprob.Setup('py_summary.xml', 'reduce.py')

R_types = ["int32", "int64", "float32", "float64"]
R_shaps = [(10 ** 3,), (10 ** 5,), (10 ** 7,), 
           (10 ** 1, 10 ** 3), (10 ** 3, 10 ** 7),
           (10 ** 1, 10 ** 2, 10 ** 1), (10 ** 1, 10 ** 2, 10 ** 7),
           (10 ** 1, 10 ** 1, 10 ** 2, 10 ** 1), 
           (10 ** 1, 10 ** 1, 10 ** 1, 10 ** 2, 10 ** 1), 
           (10 ** 2, 10 ** 1, 10 ** 1, 10 ** 1, 10 ** 2, 10 ** 1), 
           (2 ** 1, 2 ** 2, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1),
           (2 ** 1, 2 ** 2, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 10 ** 2),
           (2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 10 ** 1, 10 ** 1),
           (2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 10 ** 1, 10 ** 1, 10 ** 1),
           (2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 10 ** 1, 10 ** 1, 10 ** 1, 2 ** 1),
           (2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 10 ** 1, 10 ** 1, 10 ** 1, 2 ** 1, 2 ** 1),
           (2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 10 ** 1, 10 ** 1, 10 ** 1, 2 ** 1, 2 ** 1, 2 ** 1),
           (2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 10 ** 1, 10 ** 1, 10 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1),
           (2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 10 ** 1, 10 ** 1, 10 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1),
           (2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 10 ** 1, 10 ** 1, 10 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1),
           (2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 10 ** 1, 10 ** 1, 10 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1, 2 ** 1)]
R_order = ["C", "F"]
R_axis  = [None, 0, 1]

RAND_ARRAY_CACHE = {}
def get_cached_rand_array(shape, dtype, order):
    key = (shape, dtype, order)
    print (key)
    
    random_state = np.random.RandomState(1234)
    if "int" in shape:
        dtype_info = np.iinfo(dtype)
        arr = random_state.randint(dtype_info.min, dtype_info.max, size=shape, dtype=dtype)
    else:
        arr = 10000 * random_state.standard_normal(shape).astype(dtype)

    if order == "F":
        arr = np.asfortranarray(arr)
        
    return arr
    
def WriteTest (FileName):
    with open(FileName, 'wb') as Fw:
        Init = 0x23452111
        Fw.write (Init.to_bytes(4, byteorder='little'))
        Init = 0x23452111
        Fw.write (Init.to_bytes(4, byteorder='little'))

def LoadTest (FileName):
    with open(FileName, 'rb') as Fw:
        Value = Fw.read ()
        return Value

if __name__ == '__main__':
    try:
        Value = bytearray (LoadTest (sys.argv[1]))
        
        T = R_types [Value[0]%len(R_types)]
        S = R_shaps [Value[1]%len(R_shaps)]
        O = R_order [Value[2]%len(R_order)]
        
        ary = get_cached_rand_array (S, T, O)
        axis = R_axis[Value[3]%len(R_axis)]
        
        bn.nanmin(ary, axis=axis)
        bn.nanmax(ary, axis=axis)
        bn.nanargmin(ary, axis=axis)
        bn.nanargmax(ary, axis=axis)
        bn.nanmean(ary, axis=axis)
        bn.nanstd(ary, axis=axis)
        bn.nanvar(ary, axis=axis)
        bn.median(ary, axis=axis)
        bn.nanmedian(ary, axis=axis)
        bn.ss(ary, axis=axis)
        
        bn.rankdata(ary)
        bn.nanrankdata(ary)
        bn.push(ary)
        
        ptNum = Value[4]/2
        if ptNum == 0:
            ptNum = 2
        pt = int (S[0] // ptNum)
        bn.partition(ary, pt)
        bn.argpartition(ary, pt)
 
    except Exception as e:
        print (e)
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)