import sys
from tink.jwt import _jwt_format
from tink.jwt import _json_util
import pyprob

pyprob.Setup('py_summary.xml', 'jwt_json.py')


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
        if isinstance (raw_data, str):     
            raw_data = raw_data.encode('utf8')
        else:
            raw_data = bytes (raw_data)
        
        _json_util.json_loads(raw_data)
        encoded_data = _jwt_format.base64_encode(raw_data)
        decoded_data = _jwt_format.base64_decode (encoded_data)
        _json_util.json_loads(decoded_data)
        
    except Exception as e:
        print (e)
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)

