import sys
import io
import tink
from tink import cleartext_keyset_handle
from tink import hybrid

associated_data = b"fuzz_association"

hybrid.register ()

def init_keyset (keyset_file):
    json_keyset = ''
    with open (keyset_file, 'r') as f:
	    json_keyset = f.read()

    reader = tink.JsonKeysetReader(json_keyset)
    private_keyset_handle = cleartext_keyset_handle.read(reader)
    hybrid_primitive = private_keyset_handle.primitive(hybrid.HybridDecrypt)
    return hybrid_primitive


def hybrid_decrypt (primitive, data):
    primitive.decrypt (data, associated_data)
    
def load (file):
    with open(file, 'rb') as f:
        data = f.read()
        return data

if __name__ == '__main__':
    data = load (sys.argv[1])
    
    hybrid_primitive = init_keyset ('keyset.json')
    hybrid_decrypt (hybrid_primitive, data)

