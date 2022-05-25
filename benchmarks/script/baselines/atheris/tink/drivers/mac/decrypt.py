import sys
import io
import atheris

with atheris.instrument_imports():
    import tink
    from tink import cleartext_keyset_handle
    from tink import mac

mac.register ()

def init_keyset (keyset_file):
    json_keyset = ''
    with open (keyset_file, 'r') as f:
	    json_keyset = f.read()

    reader = tink.JsonKeysetReader(json_keyset)
    keyset_handle = cleartext_keyset_handle.read(reader)
    mac_primitive = keyset_handle.primitive(mac.Mac)
    return mac_primitive
    
mac_primitive = init_keyset ('keyset.json')

@atheris.instrument_func  
def RunTest (data):
    try:
        data = load (sys.argv[1])
        raw_data = [b"",
                    b":KKllk???????????2222??????kjfj",
                    b"\x86afjsahshjfksfkhalfkjjjjjjjeeeeeeeee?????????????has"]
        
        for data in raw_data:
            tag = mac_primitive.compute_mac(data)
            mac_primitive.verify_mac (tag, data)
    except Exception as e:
        print (e)
    

if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()

