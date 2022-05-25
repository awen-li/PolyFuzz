import sys
import io
import atheris

with atheris.instrument_imports():
    import tink
    from tink import cleartext_keyset_handle
    from tink import streaming_aead

associated_data = b"fuzz_association"

streaming_aead.register ()

def init_keyset (keyset_file):
    json_keyset = ''
    with open (keyset_file, 'r') as f:
	    json_keyset = f.read()

    reader = tink.JsonKeysetReader(json_keyset)
    keyset_handle = cleartext_keyset_handle.read(reader)
    streaming_aead_primitive = keyset_handle.primitive(streaming_aead.StreamingAead)
    return streaming_aead_primitive

streaming_aead_primitive = init_keyset ('keyset.json')

@atheris.instrument_func  
def RunTest (data):
    try:
        ciphertext_src = io.BytesIO (data)
        with streaming_aead_primitive.new_decrypting_stream(ciphertext_src, associated_data) as ds:
            ds.read()
    except Exception as e:
        print (e)

if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()
    

