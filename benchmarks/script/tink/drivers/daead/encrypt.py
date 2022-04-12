import os
import tink
from tink import daead
from tink import cleartext_keyset_handle

associated_data = b"fuzz_association"
daead.register ()
keyset_handle = tink.new_keyset_handle(daead.deterministic_aead_key_templates.AES256_SIV)
daead_primitive = keyset_handle.primitive(daead.DeterministicAead)

def write_keyset (keyset_handle):
    with open('keyset.json', 'w') as keyset_file:
        cleartext_keyset_handle.write(tink.JsonKeysetWriter(keyset_file), keyset_handle)

def daead_encrypt (no, data):
     
    output_file = open("tests/test-" + str (no), 'wb')
    with output_file as of:
        ciphertext = daead_primitive.encrypt_deterministically(data, associated_data)
        of.write(ciphertext)


if __name__ == '__main__':
    raw_data = [b"",
                b":KKllk???????????2222??????kjfj",
                b"\x86afjsahshjfksfkhalfkjjjjjjjeeeeeeeee?????????????has"]
    no = 0
    for data in raw_data:
        daead_encrypt (no, data)
        no += 1
    
    write_keyset (keyset_handle)
