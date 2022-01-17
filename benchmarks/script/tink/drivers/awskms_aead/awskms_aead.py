import sys
import os
from tink.integration import awskms
from tink.testing import helper
import pyprob

pyprob.Setup('py_summary.xml', 'awskms_aead.py')

CREDENTIAL_PATH = os.path.join(helper.tink_root_path(), 'testdata/aws_credentials_cc.txt')
KEY_URI = 'aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f'

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
        
        aws_client = awskms.AwsKmsClient(KEY_URI, CREDENTIAL_PATH)
        aead = aws_client.get_aead(KEY_URI)
        
        asso_set = [b'hello', b'xxxxxxxxxxxxxxxxxxx', b'1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111']
        for asso in asso_set:
            print ("#######asso is %s" %asso)
            cipher_data = aead.encrypt(raw_data, asso)
            aead.decrypt(cipher_data, asso)
        
    except Exception as e:
        print (e)
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)

