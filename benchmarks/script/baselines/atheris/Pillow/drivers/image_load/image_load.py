import sys
import atheris

with atheris.instrument_imports():
    from PIL import Image

seed_path = "seed.bin"

def WriteSeed (data):
    F = open (seed_path, "wb")
    F.write (data)
    F.close ()

@atheris.instrument_func  
def RunTest (data):
    WriteSeed (data)
    try:
        with Image.open(seed_path) as im:
            im.load()  
    except Exception as e:
        print (e)

if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()
