import sys
import atheris

with atheris.instrument_imports(key="pycurl"):
    import pycurl



@atheris.instrument_func    
def RunTest (InputData):

    fdp = atheris.FuzzedDataProvider(InputData)
    original = fdp.ConsumeString(sys.maxsize)

    sftp_server = 'localhost'

    try:
        c = pycurl.Curl()
        c.setopt(c.URL, sftp_server)
        c.setopt(c.VERBOSE, True)
        c.setopt(c.SSH_KNOWNHOSTS, original)
        c.perform()
        c.close()

    except Exception as e:
        pass
        

if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()