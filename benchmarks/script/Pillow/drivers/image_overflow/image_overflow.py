import sys
import pyprob
from PIL import Image
from io import BytesIO

pyprob.Setup('py_summary.xml', 'image_overflow.py')


def LoadInput (seedFile):
    Bytes = None
    with open(seedFile, 'rb') as bf:
        Bytes = bf.read()
    return Bytes
    
if __name__ == '__main__':
    try:
        Bytes = LoadInput (sys.argv[1])
        with Image.open(BytesIO(Bytes)) as im:
            im.load()
            test_output = BytesIO()
            im.save(test_output, "JPEG2000")
            test_output.seek(0)
            test_output.read()
        
    except Exception as e:
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)
    
