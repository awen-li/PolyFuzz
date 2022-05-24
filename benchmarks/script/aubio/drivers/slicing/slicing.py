import sys
import pyprob
from aubio import source, sink

pyprob.Setup('py_summary.xml', 'slicing.py')

if __name__ == '__main__':
    try:
        duration = 0.5
        hopsize = 256
        slice_n, total_frames_written, read = 0, 0, hopsize
        
        f = source(sys.argv[1], 0, hopsize)
        samplerate = f.samplerate
        g = sink("tmp_aubio", samplerate)

        while read == hopsize:
            vec, read = f()

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
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)
    
