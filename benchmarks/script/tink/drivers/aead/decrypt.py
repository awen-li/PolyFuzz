import sys
import tink
from tink import aead
from tink import cleartext_keyset_handle
import pyprob

pyprob.Setup('py_summary.xml', 'decrypt.py')

associated_data = b"fuzz_association"
aead.register ()

def init_keyset (keyset_file):
    json_keyset = ''
    with open (keyset_file, 'r') as f:
	    json_keyset = f.read()

    reader = tink.JsonKeysetReader(json_keyset)
    keyset_handle = cleartext_keyset_handle.read(reader)
    aead_primitive = keyset_handle.primitive(aead.Aead)
    return aead_primitive


def load (file):
    with open(file, 'rb') as f:
        data = f.read()
        return data

if __name__ == '__main__':
    data = load (sys.argv[1])
    
    aead_primitive = init_keyset ('keyset.json')
    aead_primitive.decrypt(data, associated_data)

