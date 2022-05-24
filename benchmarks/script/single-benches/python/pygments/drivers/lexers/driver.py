
import sys
import pygments
import pygments.formatters.html
import pygments.lexers
import atheris
import pyprob

pyprob.Setup('py_summary.xml', 'driver.py')

formatter = pygments.formatters.html.HtmlFormatter()
# pygments.LEXERS.values() is a list of tuples like this, with some of then empty:
# (textual class name, longname, tuple of aliases, tuple of filename patterns, tuple of mimetypes)
LEXERS = [l[2][0] for l in pygments.lexers.LEXERS.values() if l[2]]

def LoadBytes (FName):
    bytes = None
    with open (FName, "rb") as bf:
        bytes = bf.read()
    return bytes

if __name__ == "__main__":
    try:
        data = LoadBytes (sys.argv[1])
        
        fdp = atheris.FuzzedDataProvider(data)
        random_lexer = pygments.lexers.get_lexer_by_name(fdp.PickValueInList(LEXERS))
        str_data = fdp.ConsumeUnicode(atheris.ALL_REMAINING)

        pygments.highlight(str_data, random_lexer, formatter)
    except Exception as e:
        print (e)
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)
