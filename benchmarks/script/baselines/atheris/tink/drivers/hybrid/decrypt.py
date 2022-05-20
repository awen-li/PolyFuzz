import sys
import io
import atheris

with atheris.instrument_imports():
    import tink
    from tink import cleartext_keyset_handle
    from tink import hybrid

hybrid.register ()

def init_keyset (keyset_file):
    json_keyset = ''
    with open (keyset_file, 'r') as f:
	    json_keyset = f.read()

    reader = tink.JsonKeysetReader(json_keyset)
    private_keyset_handle = cleartext_keyset_handle.read(reader)
    hybrid_primitive = private_keyset_handle.primitive(hybrid.HybridDecrypt)
    return hybrid_primitive

hybrid_primitive = init_keyset ('keyset.json')
 
@atheris.instrument_func  
def RunTest (data):
    try:      
        hybrid_primitive.decrypt (data, associated_data)
    except Exception as e:
        print (e) 

if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()
