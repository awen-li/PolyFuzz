import sys
import atheris

with atheris.instrument_imports(key="aubio"):
    import aubio

@atheris.instrument_func  
def RunAubio (path):
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
        pass
    return s


def TestOneInput(data):  
    fdp = atheris.FuzzedDataProvider(data)
    original = fdp.ConsumeBytes(10)
    RunAubio(original)

    
if __name__ == '__main__':
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

        
    
