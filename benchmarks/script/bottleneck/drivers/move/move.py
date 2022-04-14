import sys
import pyprob
import ujson


pyprob.Setup('py_summary.xml', 'encode.py')

def LoadInput (TxtFile):
    Content = ""
    with open(TxtFile, 'r', encoding='latin1') as txfile:
        for line in txfile:
            Content = line.replace("\n", "")
            break
    return Content
    
params = [
            ["int32", "int64", "float32", "float64"],
            [(10 ** 3,), (10 ** 5,), (10 ** 7,)],
            [10],
        ]

RAND_ARRAY_CACHE = {}
    
def get_cached_rand_array(shape, dtype, order):
    key = (shape, dtype, order)
    if key not in RAND_ARRAY_CACHE:
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
    InputData = eval (LoadInput (sys.argv[1]))
    enc = ujson.encode(InputData)
    dec = ujson.decode(enc)
    enc = ujson.dumps (InputData)
    dec = ujson.loads(enc)
    print (dec)
