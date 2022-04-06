import sys
import io
import tink
from tink import cleartext_keyset_handle
from tink import daead

associated_data = b"fuzz_association"

daead.register ()

def init_keyset (keyset_file):
    json_keyset = ''
    with open (keyset_file, 'r') as f:
	    json_keyset = f.read()

    reader = tink.JsonKeysetReader(json_keyset)
    keyset_handle = cleartext_keyset_handle.read(reader)
    daead_primitive = keyset_handle.primitive(daead.DeterministicAead)
    return daead_primitive


def daead_decrypt (primitive, data):
    primitive.decrypt_deterministically (data, associated_data)
    
def load (file):
    with open(file, 'rb') as f:
        data = f.read()
        print (len (data))
        return data

if __name__ == '__main__':
    data = load (sys.argv[1])
    
    daead_primitive = init_keyset ('keyset.json')
    daead_decrypt (daead_primitive, data)

