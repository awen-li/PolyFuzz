import sys
import numpy as np
    
R_types = ["int32", "int64", "float32", "float64"]
R_shaps = [(10 ** 3,), (10 ** 24,), (10 ** 3, 10 ** 3), [(10 ** 7, 10 ** 24)], [(10 ** 7, 10 ** 14, 10 ** 28)]]
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
	
    ary = get_cached_rand_array ((10 ** 3,), "int32", "C")
    print (ary)
