import sys
import atheris
try:
    from io import BytesIO
except ImportError:
    from StringIO import StringIO as BytesIO

with atheris.instrument_imports(key="pycurl"):
    import pycurl

import sys

@atheris.instrument_func    
def RunTest (InputData):

    fdp = atheris.FuzzedDataProvider(InputData)
    original = fdp.ConsumeString(sys.maxsize)
    PY3 = sys.version_info[0] > 2

    try:
        mail_server = 'smtp://localhost'
        mail_from = 'sender@example.org'
        mail_to = 'addressee@example.net'

        c = pycurl.Curl()
        c.setopt(c.URL, mail_server)
        c.setopt(c.MAIL_FROM, mail_from)
        c.setopt(c.MAIL_RCPT, [mail_to])

        message = '''\
        From: %s
        To: %s
        Subject: PycURL SMTP example
        %s
        ''' % (mail_from, mail_to, original)

        if PY3:
            message = message.encode('ascii')

        # libcurl does not perform buffering, therefore
        # we need to wrap the message string into a BytesIO or StringIO.
        io = BytesIO(message)
        c.setopt(c.READDATA, io)

        # If UPLOAD is not set, libcurl performs SMTP VRFY.
        # Setting UPLOAD to True sends a message.
        c.setopt(c.UPLOAD, True)

        # Observe SMTP conversation.
        c.setopt(c.VERBOSE, True)
        c.perform()

    except Exception as e:
        pass
        

if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()