import sys
import tink
from tink import aead
from tink import cleartext_keyset_handle

import atheris

#with atheris.instrument_imports(key="tink"):
with atheris.instrument_imports(key="tink"):
    import tink
          
@atheris.instrument_func    
def RunTest (InputData):

    fdp = atheris.FuzzedDataProvider(InputData)
    #original = fdp.ConsumeString(sys.maxsize)
    original = fdp.ConsumeBytes(sys.maxsize)

    aead.register()

    keyset = r"""{
        "key": [{
            "keyData": {
                "keyMaterialType":
                    "SYMMETRIC",
                "typeUrl":
                    "type.googleapis.com/google.crypto.tink.AesGcmKey",
                "value":
                    "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
            },
            "keyId": 294406504,
            "outputPrefixType": "TINK",
            "status": "ENABLED"
        }],
        "primaryKeyId": 294406504
    }"""

    keyset_handle = cleartext_keyset_handle.read(tink.JsonKeysetReader(keyset))
    primitive = keyset_handle.primitive(aead.Aead)
    ciphertext = primitive.encrypt(b'msg', b'associated_data')
    try:
        primitive.decrypt(original, b'associated_data')
    except:
        pass


if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()