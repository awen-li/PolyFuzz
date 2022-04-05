import tink
from tink import aead
from tink import cleartext_keyset_handle

associated_data = b"fuzz_association"
aead.register ()
keyset_handle = tink.new_keyset_handle(aead.aead_key_templates.AES256_GCM)
aead_primitive = keyset_handle.primitive(aead.Aead)

def write_keyset (keyset_handle):
    with open('keyset.json', 'w') as keyset_file:
        cleartext_keyset_handle.write(tink.JsonKeysetWriter(keyset_file), keyset_handle)

def aead_encrypt (no, data):  
    ciphertext = aead_primitive.encrypt(data, associated_data)  
    filename = 'tests/test-' + str (no)
    with open(filename, 'wb') as f:
        f.write(ciphertext)


if __name__ == '__main__':
    raw_data = [b"",
                b":KKllk???????????????2222??????kjfj",
                b"\x86afkjshfksjdhfkjsdhasalfkjjjjjjjjeeeeeeeeeeeee???????; ??????????has"]
    no = 0
    for data in raw_data:
        aead_encrypt (no, data)
        no += 1

    write_keyset (keyset_handle)