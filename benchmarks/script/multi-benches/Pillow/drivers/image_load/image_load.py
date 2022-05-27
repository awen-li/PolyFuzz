import sys
import pyprob
from PIL import Image

pyprob.Setup('py_summary.xml', 'image_load.py')


if __name__ == '__main__':
    try:
        with Image.open(sys.argv[1]) as im:
            im.load()
        
    except Exception as e:
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)
    
