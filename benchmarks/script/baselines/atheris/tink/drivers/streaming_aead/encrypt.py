import os
import tink
from tink import streaming_aead
from tink import cleartext_keyset_handle

associated_data = b"fuzz_association"
streaming_aead.register ()
keyset_handle = tink.new_keyset_handle(streaming_aead.streaming_aead_key_templates.AES256_CTR_HMAC_SHA256_4KB)
streaming_aead_primitive = keyset_handle.primitive(streaming_aead.StreamingAead)

def write_keyset (keyset_handle):
    with open('keyset.json', 'w') as keyset_file:
        cleartext_keyset_handle.write(tink.JsonKeysetWriter(keyset_file), keyset_handle)

def aead_encrypt (no, data):
     
    output_file = open("tests/test-" + str (no), 'wb')
    with streaming_aead_primitive.new_encrypting_stream(output_file, associated_data) as enc_stream:
        bytes_written = enc_stream.write(data)


if __name__ == '__main__':
    raw_data = [b"",
                b":KKllk???????????2222??????kjfj",
                b"\x86afjsahshjfksfkhalfkjjjjjjjeeeeeeeee?????????????has"]
    no = 0
    for data in raw_data:
        aead_encrypt (no, data)
        no += 1
    
    write_keyset (keyset_handle)
