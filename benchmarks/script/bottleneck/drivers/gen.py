import sys
import random
import numpy as np
    
R_types = ["int32", "int64", "float32", "float64"]
R_shaps = [(10 ** 3,), (10 ** 1, 10 ** 3), (10 ** 1, 10 ** 2, 10 ** 1)]
R_order = ["C", "F"]

RAND_ARRAY_CACHE = {}
    
def get_cached_rand_array(shape, dtype, order):
    key = (shape, dtype, order)
    print (key)
    if key not in RAND_ARRAY_CACHE.keys():
        assert order in ["C", "F"]
        random_state = np.random.RandomState(1234)
        if "int" in shape:
            dtype_info = np.iinfo(dtype)
            arr = random_state.randint(
                dtype_info.min, dtype_info.max, size=shape, dtype=dtype
            )
        else:
            arr = 10000 * random_state.standard_normal(shape).astype(dtype)

        if order == "F":
            arr = np.asfortranarray(arr)

        assert arr.flags[order + "_CONTIGUOUS"]

        RAND_ARRAY_CACHE[key] = arr

    return RAND_ARRAY_CACHE[key].copy(order=order)

if __name__ == '__main__':
	
    testDir = sys.argv[1]
    CaseNum = int (sys.argv[2])
    
    for i in range (0, CaseNum):
        T = R_types [random.randint (0, len(R_types)-1)]
        S = R_shaps [random.randint (0, len(R_shaps)-1)]
        O = R_order [random.randint (0, len(R_order)-1)]
        ary = get_cached_rand_array (S, T, O)
        
        FileName = testDir + "/test-" + str(i)
        with open(FileName, 'w') as Fw:
            Fw.write (str(ary))
