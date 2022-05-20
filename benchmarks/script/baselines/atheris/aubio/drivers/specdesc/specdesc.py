import sys
import pyprob
import numpy as np
from aubio import source, pvoc, specdesc

pyprob.Setup('py_summary.xml', 'specdesc.py')

win_s   = 512                 
hop_s   = win_s // 4          
methods = ['default', 'energy', 'hfc', 'complex', 'phase', 'specdiff', 'kl',
           'mkl', 'specflux', 'centroid', 'slope', 'rolloff', 'spread', 'skewness',
           'kurtosis', 'decrease',]

if __name__ == '__main__':
    try:
        all_descs = {}
        o = {}
        
        s = source(sys.argv[1])
        samplerate = s.samplerate
        
        pv = pvoc(win_s, hop_s)

        for method in methods:
            cands = []
            all_descs[method] = np.array([])
            o[method] = specdesc(method, win_s)
        
        while True:
            samples, read = s()
            fftgrain = pv(samples)
            for method in methods:
                specdesc_val = o[method](fftgrain)[0]
            if read < hop_s: break

    except Exception as e:
        print (e)
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)
    
