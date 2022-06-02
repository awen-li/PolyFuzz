import sys
import atheris

with atheris.instrument_imports(key="Crypto"):
    from Crypto.Cipher import AES

key_path  = "key.bin"
seed_path = "seed.bin"

def GetKey ():
    key = None
    with open (key_path, "rb") as F:
        key = F.read ()
    return key
    
def WriteTest (data):
    with open (seed_path, "wb") as F:
        F.write (data)

@atheris.instrument_func    
def RunDecrypt (seed_path):
    try:
        file_in = open(seed_path, "rb")
        nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

        key = GetKey()     
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)

    except Exception as e:
        print (e)
 
def RunTest (bytes):
    WriteTest (bytes)
    RunDecrypt (seed_path)
    
if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()