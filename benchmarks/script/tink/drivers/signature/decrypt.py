import sys
import io
import tink
from tink import cleartext_keyset_handle
from tink import signature
import pyprob

pyprob.Setup('py_summary.xml', 'decrypt.py')

signature.register()

def init_keyset (keyset_file):
    json_keyset = ''
    with open (keyset_file, 'r') as f:
	    json_keyset = f.read()

    reader = tink.JsonKeysetReader(json_keyset)
    private_keyset_handle = cleartext_keyset_handle.read(reader)
    
    public_keyset_handle  = private_keyset_handle.public_keyset_handle()
    signature_primitive   = public_keyset_handle.primitive(signature.PublicKeyVerify)
    
    return private_keyset_handle, signature_primitive
  
def load (file):
    with open(file, 'rb') as f:
        data = f.read()
        return data

if __name__ == '__main__':
    data = load (sys.argv[1])
    
    raw_data = [b"",
                b":KKllk???????????2222??????kjfj",
                b"\x86afjsahshjfksfkhalfkjjjjjjjeeeeeeeee?????????????has"]
    private_keyset_handle, signature_primitive = init_keyset ('keyset.json')
    
    for data in raw_data:
        signer = private_keyset_handle.primitive(signature.PublicKeySign)
        signature_data = signer.sign(data)
    
        signature_primitive.verify (signature_data, data)

