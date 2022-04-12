import sys
import io
import tink
from tink import cleartext_keyset_handle
from tink import streaming_aead
import pyprob

pyprob.Setup('py_summary.xml', 'decrypt.py')

associated_data = b"fuzz_association"

streaming_aead.register ()

def init_keyset (keyset_file):
    json_keyset = ''
    with open (keyset_file, 'r') as f:
	    json_keyset = f.read()

    reader = tink.JsonKeysetReader(json_keyset)
    keyset_handle = cleartext_keyset_handle.read(reader)
    streaming_aead_primitive = keyset_handle.primitive(streaming_aead.StreamingAead)
    return streaming_aead_primitive


def streaming_aead_decrypt (primitive, data):
    ciphertext_src = io.BytesIO (data)
    with primitive.new_decrypting_stream(ciphertext_src, associated_data) as ds:
        ds.read()
    
def load (file):
    with open(file, 'rb') as f:
        data = f.read()
        return data

if __name__ == '__main__':
    data = load (sys.argv[1])
    
    streaming_aead_primitive = init_keyset ('keyset.json')
    streaming_aead_decrypt (streaming_aead_primitive, data)

