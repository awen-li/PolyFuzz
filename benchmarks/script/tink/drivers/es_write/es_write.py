import sys
import io
from tink import core
from tink import streaming_aead
from tink.streaming_aead import _raw_streaming_aead
from tink.testing import bytes_io
import pyprob

pyprob.Setup('py_summary.xml', 'es_write.py')

B_X80 = b'\x80'
B_AAD_ = b'aa' + B_X80
B_ASSOC_ = b'asso' + B_X80

def get_raw_primitive():
  key_data = core.Registry.new_key_data(streaming_aead.streaming_aead_key_templates.AES128_CTR_HMAC_SHA256_4KB)
  return core.Registry.primitive(key_data, _raw_streaming_aead.RawStreamingAead)

def LoadInput (TxtFile):
    Content = ""
    with open(TxtFile, 'r', encoding='latin1') as txfile:
        for line in txfile:
            Content = line.replace("\n", "")
            break
    return Content

if __name__ == '__main__':
    try:
        Data = eval (LoadInput (sys.argv[1]))
        print (Data)
        streaming_aead.register()
        
        #write
        raw_primitive = get_raw_primitive()
        ct_destination = bytes_io.BytesIOWithValueAfterClose()
        with raw_primitive.new_raw_encrypting_stream(ct_destination, B_AAD_) as es:
            es.write(Data)
        
        #read
        data_len = len (Data)
        ct_source = io.BytesIO(ct_destination.value_after_close())
        with raw_primitive.new_raw_decrypting_stream(ct_source, B_AAD_, close_ciphertext_source=True) as ds:
            ds.read(data_len)
            ds.read(data_len*2)   
    except Exception as e:
        print (e)
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)

