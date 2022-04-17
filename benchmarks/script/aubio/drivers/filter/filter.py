import sys
import pyprob
import aubio

pyprob.Setup('py_summary.xml', 'source.py')


if __name__ == '__main__':
    try:
        s = aubio.source(sys.argv[1])
        samplerate = s.samplerate
        
        f = aubio.digital_filter(7)
        f.set_a_weighting(samplerate)
        
        while True:
            samples, read = s()
            filtered_samples = f(samples)
            if read < s.hop_size:
                break
    except Exception as e:
        print (e)
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)
    
