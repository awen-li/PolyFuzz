import sys
import tink
from tink import prf
from tink.testing import keyset_builder
import pyprob

pyprob.Setup('py_summary.xml', 'prfset_wrapper.py')

TEMPLATE = prf.prf_key_templates.HMAC_SHA256

def LoadInput (TxtFile):
    Content = ""
    with open(TxtFile, 'r', encoding='latin1') as txfile:
        for line in txfile:
            Content = line.replace("\n", "")
            break
    return Content  

if __name__ == '__main__':
    try:
        raw_data = eval (LoadInput (sys.argv[1]))
        if isinstance (raw_data, str):     
            raw_data = raw_data.encode('utf8')
        else:
            raw_data = bytes (raw_data)
        
        prf.register()
        
        keyset_handle = tink.new_keyset_handle(TEMPLATE)
        primitive = keyset_handle.primitive(prf.PrfSet)
        
        length_set = [0, 16, 31, 65535, 11111165535]
        for length in length_set:
            output = primitive.primary().compute(raw_data, output_length=length)
        
    except Exception as e:
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)

