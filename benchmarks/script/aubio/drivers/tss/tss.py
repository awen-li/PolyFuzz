import sys
import pyprob
from aubio import source, sink

pyprob.Setup('py_summary.xml', 'tss.py')

if __name__ == '__main__':
    try:
        samplerate = 44100
        win_s = 1024       # fft size
        hop_s = win_s // 8 # block size

        f = source(sys.argv[1], samplerate, hop_s)
        g = sink(sys.argv[2], samplerate)
        h = sink(sys.argv[3], samplerate)

        pva = pvoc(win_s, hop_s)    # a phase vocoder
        pvb = pvoc(win_s, hop_s)    # another phase vocoder
        t = tss(win_s, hop_s)       # transient steady state separation

        t.set_threshold(0.01)
        t.set_alpha(3.)
        t.set_beta(4.)

        read = hop_s

        while read:
            samples, read = f()         
            spec = pva(samples)           
            trans_spec, stead_spec = t(spec)
            transients = pva.rdo(trans_spec)
            steadstate = pvb.rdo(stead_spec)
            g(transients, read)        
            h(steadstate, read)               

        del f, g, h                           

    except Exception as e:
        print (e)
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)
    
