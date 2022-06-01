import os
import tink
from tink import hybrid
from tink import cleartext_keyset_handle

associated_data = b"fuzz_association"
hybrid.register ()
private_keyset_handle = tink.new_keyset_handle(hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM)
public_keyset_handle = private_keyset_handle.public_keyset_handle()

hybrid_primitive = public_keyset_handle.primitive(hybrid.HybridEncrypt)

def write_keyset (keyset_handle):
    with open('keyset.json', 'w') as keyset_file:
        cleartext_keyset_handle.write(tink.JsonKeysetWriter(keyset_file), keyset_handle)

def hybrid_encrypt (no, data):
     
    output_file = open("tests/test-" + str (no), 'wb')
    with output_file as of:
        ciphertext = hybrid_primitive.encrypt(data, associated_data)
        of.write(ciphertext)


if __name__ == '__main__':
    raw_data = [b"",
                b":KKllk???????????2222??????kjfj",
                b"\x86afjsahshjfksfkhalfkjjjjjjjeeeeeeeee?????????????has"]
    no = 0
    for data in raw_data:
        hybrid_encrypt (no, data)
        no += 1
    
    write_keyset (private_keyset_handle)
