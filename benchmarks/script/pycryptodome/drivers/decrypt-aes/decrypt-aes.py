import sys
import pyprob
from Crypto.Cipher import AES

key_path = "key.bin"
pyprob.Setup('py_summary.xml', 'decrypt-aes.py')


def GetKey ():
    key = None
    with open (key_path, "rb") as F:
        key = F.read ()
    return key

if __name__ == '__main__':
    try:
        file_in = open(sys.argv[1], "rb")
        nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

        key = GetKey()
        
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)


    except Exception as e:
        print ("Exception --> ", end="")
        print (e)
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)
    
