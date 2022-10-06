import sys
import aubio

def TestEntry(path):

    s = None
    try:
        s = aubio.source(path)
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
    return s
    
if __name__ == '__main__':
    while True:
        s = TestEntry (sys.argv[1])
        del s
        
    
