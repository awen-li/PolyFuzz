import sys
import pyprob
import aubio
import numpy as np

pyprob.Setup('py_summary.xml', 'fig_process.py')


if __name__ == '__main__':
    try:
        pass
    except Exception as e:
        print (e)
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)
    
