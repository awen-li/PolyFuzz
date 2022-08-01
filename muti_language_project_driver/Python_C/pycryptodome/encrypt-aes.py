import sys
import atheris

with atheris.instrument_imports():
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes

key_path = "key.bin"

def GetKey ():
    import os
    key = None
    if os.path.exists (key_path) is False:
        with open (key_path, "wb") as F:
            key = get_random_bytes(32)
            F.write (key)
        return key
    else:
        with open (key_path, "rb") as F:
            key = F.read ()
        return key

@atheris.instrument_func    
def RunTest (data):
    fdp = atheris.FuzzedDataProvider(data)
    try: 
        key = GetKey()
        
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(fdp)

        with open("encrypted.bin", "wb") as F:
            [ F.write(x) for x in (cipher.nonce, tag, ciphertext) ]

    except Exception as e:
        pass

if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()