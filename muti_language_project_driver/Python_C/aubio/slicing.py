import sys
import atheris

with atheris.instrument_imports(key="aubio"):
    from aubio import source, sink


@atheris.instrument_func  
def RunAubio (path):
    s = None
    try:
        duration = 0.5
        hopsize = 256
        slice_n, total_frames_written, read = 0, 0, hopsize
        
        s = source(path, 0, hopsize)
        samplerate = s.samplerate
        g = sink("tmp_aubio", samplerate)

        while read == hopsize:
            vec, read = s()

            start_of_next_region = int(duration * samplerate * (slice_n + 1))
            remaining = start_of_next_region - total_frames_written
			
            if remaining <= read:
                g(vec[0:remaining], remaining)
                del g
                slice_n += 1
                g = sink("tmp_aubio", samplerate)
                g(vec[remaining:read], read - remaining)
            else:
                g(vec[0:read], read)
            total_frames_written += read

    except Exception as e:
        print (e)

    return s

def TestOneInput(data):  
    fdp = atheris.FuzzedDataProvider(data)
    RunAubio(fdp)



    
if __name__ == '__main__':
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()
    
