import os
import tink
from tink import signature
from tink import cleartext_keyset_handle

signature.register ()

keyset_handle = tink.new_keyset_handle(signature.signature_key_templates.ED25519)
signature_primitive = keyset_handle.primitive(signature.PublicKeySign)

def write_keyset (keyset_handle):
    with open('keyset.json', 'w') as keyset_file:
        cleartext_keyset_handle.write(tink.JsonKeysetWriter(keyset_file), keyset_handle)

def signature_encrypt (no, data):    
    output_file = open("tests/test-" + str (no), 'wb')
    with output_file as of:
        ciphertext = signature_primitive.sign(data)
        of.write(ciphertext)


if __name__ == '__main__':
    raw_data = [b"",
                b":KKllk???????????2222??????kjfj",
                b"\x86afjsahshjfksfkhalfkjjjjjjjeeeeeeeee?????????????has"]
    no = 0
    for data in raw_data:
        signature_encrypt (no, data)
        no += 1
    
    write_keyset (keyset_handle)
