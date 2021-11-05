#include <Python.h>
#include <frameobject.h>


static int lineCounter = 0;

int TraceBack(PyObject *obj, PyFrameObject *frame, int what, PyObject *arg)
{
    if(what == PyTrace_LINE)
    {
        lineCounter += 1;
        printf("line %d\n", lineCounter);
    }
    return 0;
}

int main(int argc, char *argv[])
{
    wchar_t *program = Py_DecodeLocale(argv[0], NULL);
    if (program == NULL) {
        fprintf(stderr, "Fatal error: cannot decode argv[0]\n");
        exit(1);
    }
    Py_SetProgramName(program);  /* optional but recommended */
    Py_Initialize();
    
    PyEval_SetTrace(TraceBack, NULL);
    
    char *code = "def adder(a, b):\n"
                 " return a + b\n"
                 "x = 3\n"
                 "y = 4\n"
                 "print(adder(x, y))\n";
    
    PyRun_SimpleString(code);
    Py_Finalize();
    PyMem_RawFree(program);
    
    return 0;
}
