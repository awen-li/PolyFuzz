import os
import tink
from tink import mac
from tink import cleartext_keyset_handle

mac.register ()
keyset_handle = tink.new_keyset_handle(mac.mac_key_templates.HMAC_SHA256_128BITTAG)
mac_primitive = keyset_handle.primitive(mac.Mac)

def write_keyset (keyset_handle):
    with open('keyset.json', 'w') as keyset_file:
        cleartext_keyset_handle.write(tink.JsonKeysetWriter(keyset_file), keyset_handle)

def mac_encrypt (no, data):     
    output_file = open("tests/test-" + str (no), 'wb')
    with output_file as of:
        tag = mac_primitive.compute_mac(data)
        of.write(tag)


if __name__ == '__main__':
    raw_data = [b"",
                b":KKllk???????????2222??????kjfj",
                b"\x86afjsahshjfksfkhalfkjjjjjjjeeeeeeeee?????????????has"]
    no = 0
    for data in raw_data:
        mac_encrypt (no, data)
        no += 1
    
    write_keyset (keyset_handle)
