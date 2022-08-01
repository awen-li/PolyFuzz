import sys
import atheris

with atheris.instrument_imports(key="PIL"):
    from PIL import Image

@atheris.instrument_func  
def RunTest (data):
    fdp = atheris.FuzzedDataProvider(data)
    try:
        with Image.open(fdp) as im:
            im.load()  
    except Exception as e:
        pass

if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()
