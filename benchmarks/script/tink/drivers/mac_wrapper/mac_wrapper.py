import sys
from tink import mac
from tink.testing import keyset_builder
import pyprob

pyprob.Setup('py_summary.xml', 'mac_wrapper.py')

MAC_TEMPLATE = mac.mac_key_templates.HMAC_SHA256_128BITTAG
RAW_MAC_TEMPLATE = keyset_builder.raw_template(MAC_TEMPLATE)
LEGACY_MAC_TEMPLATE = keyset_builder.legacy_template(MAC_TEMPLATE)

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
        mac.register()
        
        key_templts = [(MAC_TEMPLATE, MAC_TEMPLATE),(MAC_TEMPLATE, RAW_MAC_TEMPLATE),(MAC_TEMPLATE, LEGACY_MAC_TEMPLATE), (RAW_MAC_TEMPLATE, MAC_TEMPLATE),
                       (RAW_MAC_TEMPLATE, RAW_MAC_TEMPLATE),(RAW_MAC_TEMPLATE, LEGACY_MAC_TEMPLATE),(LEGACY_MAC_TEMPLATE, MAC_TEMPLATE),(LEGACY_MAC_TEMPLATE, RAW_MAC_TEMPLATE),(LEGACY_MAC_TEMPLATE, LEGACY_MAC_TEMPLATE)]
        for templt in key_templts:
            old_key_tmpl = templt[0]
            new_key_tmpl = templt[1]
        
            builder = keyset_builder.new_keyset_builder()
            older_key_id = builder.add_new_key(old_key_tmpl)

            builder.set_primary_key(older_key_id)
            mac1 = builder.keyset_handle().primitive(mac.Mac)

            newer_key_id = builder.add_new_key(new_key_tmpl)
            mac2 = builder.keyset_handle().primitive(mac.Mac)

            builder.set_primary_key(newer_key_id)
            mac3 = builder.keyset_handle().primitive(mac.Mac)

            builder.disable_key(older_key_id)
            mac4 = builder.keyset_handle().primitive(mac.Mac)
            
            mac_value1 = mac1.compute_mac(raw_data)
            mac1.verify_mac(mac_value1, raw_data)
            mac2.verify_mac(mac_value1, raw_data)
            mac3.verify_mac(mac_value1, raw_data)
            mac4.verify_mac(mac_value1, raw_data)
        
    except Exception as e:
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)

