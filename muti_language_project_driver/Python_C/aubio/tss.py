import sys
import atheris

with atheris.instrument_imports(key="aubio"):
    from aubio import source, sink, pvoc, tss


@atheris.instrument_func  
def RunAubio (path):
    s = g = h = None
    try:
        samplerate = 44100
        win_s = 1024       # fft size
        hop_s = win_s // 8 # block size

        s = source(path, samplerate, hop_s)
        g = sink(path+"-1.sink", samplerate)
        h = sink(path+"-2.sink", samplerate)

        pva = pvoc(win_s, hop_s)    # a phase vocoder
        pvb = pvoc(win_s, hop_s)    # another phase vocoder
        t = tss(win_s, hop_s)       # transient steady state separation

        t.set_threshold(0.01)
        t.set_alpha(3.)
        t.set_beta(4.)

        read = hop_s

        while read:
            samples, read = s()         
            spec = pva(samples)           
            trans_spec, stead_spec = t(spec)
            transients = pva.rdo(trans_spec)
            steadstate = pvb.rdo(stead_spec)
            g(transients, read)        
            h(steadstate, read)               

    except Exception as e:
        print (e)
    
    return s, g, h   


def TestOneInput(data):  
    fdp = atheris.FuzzedDataProvider(data)
    RunAubio(fdp)


if __name__ == '__main__':
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()
    
