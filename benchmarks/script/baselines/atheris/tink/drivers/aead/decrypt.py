import sys
import atheris

with atheris.instrument_imports():
    import tink
    from tink import aead
    from tink import cleartext_keyset_handle

associated_data = b"fuzz_association"
aead.register ()

def init_keyset (keyset_file):
    json_keyset = ''
    with open (keyset_file, 'r') as f:
	    json_keyset = f.read()

    reader = tink.JsonKeysetReader(json_keyset)
    keyset_handle = cleartext_keyset_handle.read(reader)
    aead_primitive = keyset_handle.primitive(aead.Aead)
    return aead_primitive

aead_primitive = init_keyset ('keyset.json')

@atheris.instrument_func  
def RunTest (data):
    try:      
        aead_primitive.decrypt(data, associated_data)    
    except Exception as e:
        print (e)

if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()
    

