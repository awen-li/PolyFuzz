import sys
import random
import numpy as np
import bottleneck as bn
import pyprob

pyprob.Setup('py_summary.xml', 'move.py')

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
        window = Value[3]
        
        bn.move_sum(ary, window)
        bn.move_mean(ary, window)
        bn.move_std(ary, window)
        bn.move_var(ary, window)
        bn.move_min(ary, window)
        bn.move_max(ary, window)
        bn.move_argmin(ary, window)
        bn.move_argmin(ary, window)
        bn.move_argmax(ary, window)
        bn.move_median(ary, window)
        bn.move_rank(ary, window)
        
        bn.replace(ary, 0, 1)
        bn.replace(ary, Value[0]%2, Value[1]%3)
    except Exception as e:
        print (e)
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)