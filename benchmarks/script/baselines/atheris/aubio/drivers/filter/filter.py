import sys
import atheris

with atheris.instrument_imports():
    import aubio

seed_path = "seed.bin"

def WriteSeed (data):
    F = open (seed_path, "wb")
    F.write (data)
    F.close ()

@atheris.instrument_func  
def RunAubio (path):
    s = None
    try:
        s = aubio.source(seed_path)
        samplerate = s.samplerate
        
        f = aubio.digital_filter(7)
        f.set_a_weighting(samplerate)
        
        while True:
            samples, read = s()
            filtered_samples = f(samples)
            if read < s.hop_size:
                break
    except Exception as e:
        pass
    return s


def TestOneInput(data):  
    WriteSeed (data)
    s = RunAubio (seed_path)
    del s
    
if __name__ == '__main__':
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

        
    
