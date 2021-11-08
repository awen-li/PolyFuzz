#include "trace.h"
#include <frameobject.h>
#include <opcode.h>
#include <pystate.h>
#include <cstddef>
#include <deque>
#include <iostream>
#include <unordered_map>

namespace pyins {

//typedef struct {
//    PyObject_HEAD			   /* Header information, we see that everything really is an object, and bytecode is also an object */	
//    int co_argcount;            /* The number of parameters that can be passed through positional parameters */
//    int co_posonlyargcount;     /* The number of parameters that can only be passed through positional parameters, new in Python 3.8 */
//    int co_kwonlyargcount;      /* The number of parameters that can only be passed by keyword parameters */
//    int co_nlocals;             /* The number of local variables in the code block, including parameters */
//    int co_stacksize;           /* The stack space required to execute the code block */
//    int co_flags;               /* Parameter type identification */
//    int co_firstlineno;         /* The line number of the code block in the corresponding file */
//    PyObject *co_code;          /* The instruction set, or bytecode, is a bytes object */
//    PyObject *co_consts;        /* Constant pool, a tuple, holds all constants in the code block. */
//    PyObject *co_names;         /* A tuple that holds variables of other scopes referenced in the code block */
//    PyObject *co_varnames;      /* A tuple that holds the variables in the current scope */
//    PyObject *co_freevars;      /* The variable in the scope of the outer function referenced by the inner function */
//    PyObject *co_cellvars;      /* The variables in the scope of the outer function that are referenced by the inner function are essentially the same as co_freevars is the same */
//
//    Py_ssize_t *co_cell2arg;    /* No need to pay attention */
//    PyObject *co_filename;      /* The file name where the code block is located */
//    PyObject *co_name;          /* The name of the code block, usually the name of a function or class */
//    PyObject *co_lnotab;        /* The corresponding relationship between bytecode instruction and line number of python source code exists in the form of PyByteObject */
//    
//    //There's no need to pay attention to the rest
//    void *co_zombieframe;       /* for optimization only (see frameobject.c) */
//    PyObject *co_weakreflist;   /* to support weakrefs to code objects */
//    void *co_extra;
//    unsigned char *co_opcache_map;
//    _PyOpcache *co_opcache;
//    int co_opcache_flag; 
//    unsigned char co_opcache_size; 
//} PyCodeObject;


//typedef struct {
//    int b_type;			/* what kind of block this is */
//    int b_handler;		/* where to jump to find handler */
//    int b_level;		/* value stack level to pop to */
//} PyTryBlock;

//typedef struct _frame {
//    PyObject_VAR_HEAD
//    struct _frame *f_back;	/* previous frame, or NULL */
//    PyCodeObject *f_code;	/* code segment */
//    PyObject *f_builtins;	/* builtin symbol table (PyDictObject) */
//    PyObject *f_globals;	/* global symbol table (PyDictObject) */
//    PyObject *f_locals;		/* local symbol table (PyDictObject) */
//    PyObject **f_valuestack;	/* points after the last local */
//    /* Next free slot in f_valuestack.  Frame creation sets to f_valuestack.
//       Frame evaluation usually NULLs it, but a frame that yields sets it
//       to the current stack top. */
//    PyObject **f_stacktop;
//    PyObject *f_trace;		/* Trace function */
//    PyObject *f_exc_type, *f_exc_value, *f_exc_traceback;
//    PyThreadState *f_tstate;
//    int f_lasti;		/* Last instruction if called */
//    int f_lineno;		/* Current line number */
//    int f_restricted;		/* Flag set if restricted operationsin this scope */
//    int f_iblock;		/* index in f_blockstack */
//     PyTryBlock f_blockstack[CO_MAXBLOCKS]; /* for try and loop blocks */
//     int f_nlocals;		/* number of locals */
//    int f_ncells;
//    int f_nfreevars;
//    int f_stacksize;		/* size of value stack */
//    PyObject *f_localsplus[1];	/* locals+stack, dynamically sized */
//} PyFrameObject;


char *StringObj (PyObject *StrObj)
{
#if 0
    PyObject *ByteObj = PyUnicode_AsEncodedString(StrObj, "UTF-8", "strict");
    if (ByteObj != NULL) 
    {
        char *Str = PyBytes_AS_STRING(ByteObj);
        Str = strdup(Str);
        Py_DECREF(ByteObj);
        return Str;
    } 
    else 
    {
        return "None";
    }
#else
    return (char*)PyUnicode_AsUTF8 (StrObj);
#endif
}

int Tracer (PyObject *obj, PyFrameObject *frame, int what, PyObject *arg)
{
    PyCodeObject *f_code  = frame->f_code;
    PyObject *co_filename = f_code->co_filename;
    PyObject *co_name     = f_code->co_name;
    
    printf ("%s : %s : %d -> ", StringObj(co_filename), StringObj (co_name), frame->f_lineno);
    switch(what)
    {
        case PyTrace_LINE:
        {
            printf("PyTrace_LINE:%d\n", what);
            break;
        }
        case PyTrace_CALL:
        {
            printf("PyTrace_CALL:%d\n", what);
            break;
        }
        case PyTrace_EXCEPTION:
        {
            printf("PyTrace_EXCEPTION:%d\n", what);
            break;
        }
        case PyTrace_RETURN:
        {
            printf("PyTrace_RETURN:%d\n", what);
            break;
        }
        case PyTrace_OPCODE:
        {
            printf("PyTrace_OPCODE:%d\n", what);
            break;
        }
        case PyTrace_C_CALL:
        {
            printf("PyTrace_C_CALL:%d\n", what);
            break;
        }
        case PyTrace_C_EXCEPTION:
        {
            printf("PyTrace_C_EXCEPTION:%d\n", what);
            break;
        }
        case PyTrace_C_RETURN:
        {
            printf("PyTrace_C_RETURN:%d\n", what);
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



void SetupTracer() 
{
    PyEval_SetTrace((Py_tracefunc)Tracer, (PyObject*)NULL);
    PyEval_SetProfile ((Py_tracefunc)Tracer, (PyObject*)NULL);
}


void PyInit() 
{
    return;
}

}  // namespace atheris
