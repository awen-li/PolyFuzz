import sys
import io
import atheris

with atheris.instrument_imports(key="tink"):
    import tink
    from tink import cleartext_keyset_handle
    from tink import signature

signature.register()

def init_keyset (keyset_file):
    json_keyset = ''
    with open (keyset_file, 'r') as f:
	    json_keyset = f.read()

    reader = tink.JsonKeysetReader(json_keyset)
    private_keyset_handle = cleartext_keyset_handle.read(reader)
    
    public_keyset_handle  = private_keyset_handle.public_keyset_handle()
    signature_primitive   = public_keyset_handle.primitive(signature.PublicKeyVerify)
    
    return private_keyset_handle, signature_primitive

private_keyset_handle, signature_primitive = init_keyset ('keyset.json')

@atheris.instrument_func  
def RunTest (data):
    try:
        raw_data = [b"",
                    b":KKllk???????????2222??????kjfj",
                    b"\x86afjsahshjfksfkhalfkjjjjjjjeeeeeeeee?????????????has"]
        
        for dt in raw_data:
            signer = private_keyset_handle.primitive(signature.PublicKeySign)
            signature_data = signer.sign(dt)
    
            signature_primitive.verify (signature_data, data)
    except Exception as e:
        print (e) 


if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()
    


