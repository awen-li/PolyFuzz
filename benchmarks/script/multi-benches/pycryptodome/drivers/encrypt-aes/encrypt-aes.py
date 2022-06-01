import sys
import pyprob
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key_path = "key.bin"
pyprob.Setup('py_summary.xml', 'encrypt-aes.py')


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

def LoadInput (FName):
    Content = ""
    with open(FName, 'rb') as f:
        Content = f.read()
    return Content

if __name__ == '__main__':
    try: 
        data = LoadInput (sys.argv[1])

        key = GetKey()
        
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        with open("encrypted.bin", "wb") as F:
            [ F.write(x) for x in (cipher.nonce, tag, ciphertext) ]


    except Exception as e:
        print ("Exception --> ", end="")
        print (e)
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)
    
