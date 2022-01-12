import tink
from tink import aead
from tink import tink_config
from tink import core

plaintext = b'your data...'
associated_data = b'context'

aead.register()

keyset_handle = tink.new_keyset_handle(aead.aead_key_templates.AES256_GCM)

# 2. Get the primitive.
aead_primitive = keyset_handle.primitive(aead.Aead)

# 3. Use the primitive.
ciphertext = aead_primitive.encrypt(plaintext, associated_data)

print ("Tink test OKay!!!!!!!!!!!");