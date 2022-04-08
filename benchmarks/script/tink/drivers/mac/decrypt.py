import sys
import io
import tink
from tink import cleartext_keyset_handle
from tink import mac
import pyprob

pyprob.Setup('py_summary.xml', 'decrypt.py')

mac.register ()

def init_keyset (keyset_file):
    json_keyset = ''
    with open (keyset_file, 'r') as f:
	    json_keyset = f.read()

    reader = tink.JsonKeysetReader(json_keyset)
    keyset_handle = cleartext_keyset_handle.read(reader)
    mac_primitive = keyset_handle.primitive(mac.Mac)
    return mac_primitive


def mac_decrypt (primitive, data):
    tag = mac_primitive.compute_mac(data)
    primitive.verify_mac (tag, data)
    
def load (file):
    with open(file, 'rb') as f:
        data = f.read()
        return data

if __name__ == '__main__':
    data = load (sys.argv[1])
    raw_data = [b"",
                b":KKllk???????????2222??????kjfj",
                b"\x86afjsahshjfksfkhalfkjjjjjjjeeeeeeeee?????????????has"]
    mac_primitive = init_keyset ('keyset.json')
    for data in raw_data:
        mac_decrypt (mac_primitive, data)

