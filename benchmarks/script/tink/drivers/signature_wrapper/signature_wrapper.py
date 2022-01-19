import sys
import tink
from tink import signature
from tink.testing import keyset_builder
import pyprob

pyprob.Setup('py_summary.xml', 'signature_wrapper.py')

TEMPLATE = signature.signature_key_templates.ECDSA_P256
LEGACY_TEMPLATE = keyset_builder.legacy_template(TEMPLATE)
RAW_TEMPLATE = keyset_builder.raw_template(TEMPLATE)

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
        if isinstance (raw_data, str):     
            raw_data = raw_data.encode('utf8')
        else:
            raw_data = bytes (raw_data)
        
        signature.register()
        
        key_templts = [(TEMPLATE, TEMPLATE),(TEMPLATE, LEGACY_TEMPLATE),(TEMPLATE, RAW_TEMPLATE),(LEGACY_TEMPLATE, TEMPLATE),(LEGACY_TEMPLATE, LEGACY_TEMPLATE),(LEGACY_TEMPLATE, RAW_TEMPLATE),
                       (RAW_TEMPLATE, TEMPLATE),(RAW_TEMPLATE, LEGACY_TEMPLATE),(RAW_TEMPLATE, RAW_TEMPLATE)]
        
        for templt in key_templts:
            old_template = templt[0]
            new_template = templt[1]
        
            builder = keyset_builder.new_keyset_builder()
            older_key_id = builder.add_new_key(old_template)
            builder.set_primary_key(older_key_id)
            
            private_handle1 = builder.keyset_handle()
            sign1 = private_handle1.primitive(signature.PublicKeySign)
            verify1 = private_handle1.public_keyset_handle().primitive(signature.PublicKeyVerify)

            newer_key_id = builder.add_new_key(new_template)
            private_handle2 = builder.keyset_handle()
            sign2 = private_handle2.primitive(signature.PublicKeySign)
            verify2 = private_handle2.public_keyset_handle().primitive(signature.PublicKeyVerify)

            builder.set_primary_key(newer_key_id)
            private_handle3 = builder.keyset_handle()
            sign3 = private_handle3.primitive(signature.PublicKeySign)
            verify3 = private_handle3.public_keyset_handle().primitive(signature.PublicKeyVerify)

            builder.disable_key(older_key_id)
            private_handle4 = builder.keyset_handle()
            sign4 = private_handle4.primitive(signature.PublicKeySign)
            verify4 = private_handle4.public_keyset_handle().primitive(signature.PublicKeyVerify)
            
            data_signature1 = sign1.sign(raw_data)
            verify1.verify(data_signature1, raw_data)
            verify2.verify(data_signature1, raw_data)
            verify3.verify(data_signature1, raw_data)
            verify4.verify(data_signature1, raw_data)
        
    except Exception as e:
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)

