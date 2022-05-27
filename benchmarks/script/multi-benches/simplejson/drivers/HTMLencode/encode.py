import sys
import pyprob
import simplejson as json
from simplejson import encoder, decoder, scanner
from simplejson.compat import PY3, long_type, b

pyprob.Setup('py_summary.xml', 'encode.py')

def LoadInput (TxtFile):
    Content = ""
    with open(TxtFile, 'r', encoding='utf-8') as f:
        Content = f.readlines()
    return Content


class BadBool:
    def __bool__(self):
        1/0
    __nonzero__ = __bool__
    
if __name__ == '__main__':
    try:
        InputData = str(LoadInput (sys.argv[1]))
        
        decoder = json.JSONDecoder()
        html_encoder = json.JSONEncoderForHTML()
        
        en = html_encoder.encode (InputData)
        decoder.decode (en)
        
        encoder.JSONEncoder(**{'skipkeys': BadBool()}).encode({})
        
        import decimal
        def bad_encoder1(*args):
            return InputData
        enc = encoder.c_make_encoder(
                None, lambda obj: str(obj),
                bad_encoder1, None, ': ', ', ',
                False, False, False, {}, False, False, False,
                None, None, 'utf-8', False, False, decimal.Decimal, False)
        
    except Exception as e:
        print ("Exception")
        print (e)
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)
    
