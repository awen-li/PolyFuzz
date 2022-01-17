import sys
import io
from absl.testing import absltest
from tink.proto import tink_pb2
from tink import core
import pyprob

pyprob.Setup('py_summary.xml', 'crypto_format.py')

   
def tink_prefix(key_id):
    key = tink_pb2.Keyset.Key()
    key.output_prefix_type = tink_pb2.TINK
    key.key_id = key_id
    prefix = core.crypto_format.output_prefix(key)
    
def legacy_prefix(key_id):
    key = tink_pb2.Keyset.Key()
    key.output_prefix_type = tink_pb2.LEGACY
    key.key_id = key_id
    prefix = core.crypto_format.output_prefix(key)
    
def crunchy_prefix(key_id):
    key = tink_pb2.Keyset.Key()
    key.output_prefix_type = tink_pb2.CRUNCHY
    key.key_id = key_id
    prefix = core.crypto_format.output_prefix(key)
    
def raw_prefix(key_id):
    key = tink_pb2.Keyset.Key()
    key.output_prefix_type = tink_pb2.RAW
    key.key_id = key_id
    prefix = core.crypto_format.output_prefix(key)

def LoadInput (TxtFile):
    Content = ""
    with open(TxtFile, 'r', encoding='latin1') as txfile:
        for line in txfile:
            Content = line.replace("\n", "")
            break
    return Content  

if __name__ == '__main__':
    try:
        raw_data = int(LoadInput (sys.argv[1]), 16)

        tink_prefix (raw_data)
        legacy_prefix (raw_data)
        crunchy_prefix (raw_data)
        raw_prefix (raw_data)
        
    except Exception as e:
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)

