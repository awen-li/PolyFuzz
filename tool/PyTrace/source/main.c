#include <Python.h>
#include <frameobject.h>

#define DEFAULT_CODE ("def adder(a, b):\n"\
                      " return a + b\n"\
                      "x = 3\n"\
                      "y = 4\n"\
                      "print(adder(x, y))\n")

int TraceBack(PyObject *obj, PyFrameObject *frame, int what, PyObject *arg)
{
    switch(what)
    {
        case PyTrace_LINE:
        {
            printf("PyTrace_LINE\n");
            break;
        }
        case PyTrace_CALL:
        {
            printf("PyTrace_CALL\n");
            break;
        }
        case PyTrace_EXCEPTION:
        {
            printf("PyTrace_EXCEPTION\n");
            break;
        }
        case PyTrace_RETURN:
        {
            printf("PyTrace_RETURN\n");
            break;
        }
        case PyTrace_OPCODE:
        {
            printf("PyTrace_OPCODE\n");
            break;
        }
        default:
        {
            printf("default: %d\n", what);
            break;
        }
    }
    
    return 0;
}

char *LoadCode (char *PyFile)
{
    assert (PyFile != NULL);
    FILE *PyF = fopen (PyFile, "r");
    assert (PyF != NULL);

    fseek(PyF, 0L, SEEK_END);
    size_t PySize = ftell(PyF) + 4;
    char *PyCode = (char *)malloc (PySize);
    assert (PyCode != NULL);
    memset (PyCode, 0, PySize);

    fseek(PyF, 0L, SEEK_SET);
    fread (PyCode, 1, PySize-4, PyF);
    
    return PyCode;
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
    
    //char *code = DEFAULT_CODE;
    char *code = LoadCode (argv[1]);
    
    PyRun_SimpleString(code);
    Py_Finalize();
    PyMem_RawFree(program);
    
    return 0;
}
