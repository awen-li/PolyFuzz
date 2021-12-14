
import bson
from bson import (BSON,
                  decode,
                  decode_all,
                  decode_file_iter,
                  decode_iter,
                  encode,
                  EPOCH_AWARE,
                  is_valid,
                  Regex)
from bson.binary import Binary, UuidRepresentation
from bson.son import SON
from bson.code import Code

import sys
import pyprob

pyprob.Setup('py_summary.xml')

def ParseText (TxtFile):
    Content = ""
    with open(TxtFile, 'r', encoding='latin1') as txfile:
        for line in txfile:
            Content = line.replace("\n", "")
            break
    return Content
    
if __name__ == '__main__':
    bson = eval (ParseText (sys.argv[1]))
    try:
        en = encode (bson)
        de = decode (en)
    except Exception as e:
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)