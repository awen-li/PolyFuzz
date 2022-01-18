import sys
import tink
from tink import daead
from tink.testing import keyset_builder
import pyprob

pyprob.Setup('py_summary.xml', 'hybrid_wrapper.py')

DAEAD_TEMPLATE = daead.deterministic_aead_key_templates.AES256_SIV
RAW_DAEAD_TEMPLATE = keyset_builder.raw_template(DAEAD_TEMPLATE)

def LoadInput (TxtFile):
    Content = ""
    with open(TxtFile, 'r', encoding='latin1') as txfile:
        for line in txfile:
            Content = line.replace("\n", "")
            break
    return Content  

if __name__ == '__main__':
    try:
        raw_data = eval (LoadInput (sys.argv[1]))
        daead.register()
        
        keyset_handle = tink.new_keyset_handle(DAEAD_TEMPLATE)
        primitive = keyset_handle.primitive(daead.DeterministicAead)
        ciphertext = primitive.encrypt_deterministically(raw_data, b'associated_data')
        primitive.decrypt_deterministically(ciphertext, b'associated_data')
        
        key_templts = [(DAEAD_TEMPLATE, DAEAD_TEMPLATE), (RAW_DAEAD_TEMPLATE, DAEAD_TEMPLATE), (DAEAD_TEMPLATE, RAW_DAEAD_TEMPLATE), (RAW_DAEAD_TEMPLATE, RAW_DAEAD_TEMPLATE)]
        for templt in key_templts:
            template1 = templt[0]
            template2 = templt[1]
        
            builder = keyset_builder.new_keyset_builder()
            older_key_id = builder.add_new_key(template1)
            builder.set_primary_key(older_key_id)
            p1 = builder.keyset_handle().primitive(daead.DeterministicAead)

            newer_key_id = builder.add_new_key(template2)
            p2 = builder.keyset_handle().primitive(daead.DeterministicAead)

            builder.set_primary_key(newer_key_id)
            p3 = builder.keyset_handle().primitive(daead.DeterministicAead)

            builder.disable_key(older_key_id)
            p4 = builder.keyset_handle().primitive(daead.DeterministicAead)
            
            ciphertext1 = p1.encrypt_deterministically(raw_data, b'ad')
            p2.decrypt_deterministically(ciphertext1, b'ad')
            p3.decrypt_deterministically(ciphertext1, b'ad')
            p4.decrypt_deterministically(ciphertext1, b'ad')
        
    except Exception as e:
        print (e)
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)

