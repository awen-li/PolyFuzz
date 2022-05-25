
import numpy as np
import sys
import atheris

with atheris.instrument_imports():
    from aubio import source, pvoc, specdesc


win_s   = 512                 
hop_s   = win_s // 4          
methods = ['default', 'energy', 'hfc', 'complex', 'phase', 'specdiff', 'kl',
           'mkl', 'specflux', 'centroid', 'slope', 'rolloff', 'spread', 'skewness',
           'kurtosis', 'decrease',]
           
seed_path = "seed.bin"

def WriteSeed (data):
    F = open (seed_path, "wb")
    F.write (data)
    F.close ()

@atheris.instrument_func  
def RunAubio (path):
    s = None
    try:
        all_descs = {}
        o = {}
        
        s = source(path)
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
    return s


def TestOneInput(data):  
    WriteSeed (data)
    s = RunAubio (seed_path)
    del s

if __name__ == '__main__':
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()
    
