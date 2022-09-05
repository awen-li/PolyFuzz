import sys
import atheris

with atheris.instrument_imports(key="ujson"):
    import ujson

@atheris.instrument_func    
def RunTest (InputData):
    try:
        fdp = atheris.FuzzedDataProvider(InputData)
        original = fdp.ConsumeString(sys.maxsize)
        InputData = eval (original)
        ujson.encode(InputData)
    except Exception as e:
        pass

if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()
