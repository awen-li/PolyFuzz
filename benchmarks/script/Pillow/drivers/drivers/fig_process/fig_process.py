import sys
import pyprob
from PIL import Image

pyprob.Setup('py_summary.xml', 'fig_process.py')

if __name__ == '__main__':
    im = Image.open(sys.argv[1])
    
