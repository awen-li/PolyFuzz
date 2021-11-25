#include "pytrace.h"
#include "op_code.h"
#include "loadbrval.h"
#include "DynTrace.h"
#include <cstddef>
#include <set>


namespace pyprob {

using namespace std;

static set<string> RegModule;
static BV_set BvSet;

void PyInit(const vector<string>& Modules, string BrValXml) 
{
    /* init tracing modules */
    RegModule.clear ();
    for (auto It = Modules.begin (); It != Modules.end (); It++)
    {
        RegModule.insert (*It);
        cout<<">>>>>>>>>>>>>>>>> add module: "<<*It<<endl;
    }

    /* load all branch variables for each function */
    BvSet.LoadBrVals(BrValXml);

    /* Init tracing: shared memory ALF++, etc. */
    DynTraceInit ();

    return;
}


static inline string BaseName(string const &Path)
{
    return Path.substr(Path.find_last_of("/") + 1);
}

static inline bool IsRegModule (string Module)
{
    auto It = RegModule.find (Module);
    if (It == RegModule.end ())
    {
        return false;
    }
    
    return true;
}


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


static inline void GetValue (PyObject *Var, ObjValue *OV)
{
    if (PyLong_Check (Var))
    {
        OV->Type   = VT_LONG;
        OV->Attr   = 0;
        OV->Length = sizeof(OV->Value);
        OV->Value  = PyLong_AsLong(Var);
        DEBUG_PRINT ("\n\t >>>>>>>>[Size:%u] [T: LONG, A:%u L: %u, V:%lx]", OV->Length, OV->Attr, OV->Length, OV->Value);
    }
    else if (PyUnicode_Check (Var))
    {
        char *UcVar = (char*)PyUnicode_AsUTF8 (Var);
        int Length  = strlen (UcVar);
        
        OV->Type   = VT_STRING;
        OV->Attr   = 0;

        int Scale = Length/sizeof(OV->Value);
        if (Scale == 0)
        {
            OV->Length = Length;
            memcpy (&OV->Value, UcVar, Length);
        }
        else
        {
            char *Value = (char *)(&OV->Value);
            for (int off = 0; off < sizeof(OV->Value); off++)
            {
                Value[off] = UcVar[off * Scale];
            }
            OV->Length = sizeof(OV->Value);
        }
        DEBUG_PRINT ("\n\t >>>>>>>>[Size:%u] Unicode, Var:%lx -> %s", OV->Length, OV->Value, UcVar);
    }
    else if (PyTuple_Check (Var))
    {
        OV->Type   = VT_SET;
        OV->Attr   = 0;    
        OV->Length = (unsigned short)Py_SIZE(Var);
        
        DEBUG_PRINT ("\n\t >>>>>>>>[Size:%u] Tuple, Var:%lx ", OV->Length, OV->Value);
    }
    else if (PyList_Check (Var))
    {
        OV->Type   = VT_LIST;
        OV->Attr   = 0;    
        OV->Length = (unsigned short)Py_SIZE(Var);

        ObjValue OVi;
        for (unsigned i = 0; i < OV->Length && i < 4; i++)
        {
            PyObject *Item = PyList_GET_ITEM(Var, i);
            GetValue (Item, &OVi);
            OV->Value ^= OVi.Value;
        }
        DEBUG_PRINT ("\n\t >>>>>>>>[Size:%u] List, Var:%lx ", OV->Length, OV->Value);
    }
    else if (PyDict_Check (Var))
    {
        OV->Type   = VT_DICT;
        OV->Attr   = 0;    
        OV->Length = (unsigned short)Py_SIZE(Var);
        
        DEBUG_PRINT ("\n\t >>>>>>>>[Size:%u] Dict, Var:%lx ", OV->Length, OV->Value);
    }
    else if (PyBytes_Check (Var))
    {
        OV->Type   = VT_STRING;
        OV->Attr   = 0;    
        OV->Length = (unsigned short)Py_SIZE(Var);
        DEBUG_PRINT ("\n\t >>>>>>>>[Size:%u] Bytes, Var:%lx ", OV->Length, OV->Value);
    }
    else if (Var == Py_None)
    {
        DEBUG_PRINT ("\n\t >>>>>>>>NoneType, Var:%p ", Var);
    }
    else
    {
        DEBUG_PRINT ("\n\t >>>>>>>>Other:%s, Var:%lx ", Var->ob_type->tp_name, OV->Value);
    }
    
    return;
}


static inline void ShowVariables (PyObject *co_varnames)
{
    int VarNum = PyTuple_GET_SIZE(co_varnames);
    if (VarNum == 0)
    {
        return;
    }

    ObjValue OV = {0};
    for (int i = 0; i < VarNum; i++)
    {
        PyObject *Var = PyTuple_GET_ITEM(co_varnames, i);
        GetValue (Var, &OV);        
    }
}

static inline void StartTracing (const char* VarName, PyObject *VarAddr, ObjValue *VarValue, TraceKey Tk)
{
    EVENT_HANDLE Eh = AllocEvent();
    assert (Eh != NULL);

    unsigned Esize = 0;
    Esize = EncodeEvent(Eh, Esize, ET_VALNAME, strlen(VarName), (BYTE*)VarName);
    Esize = EncodeEvent(Eh, Esize, ET_VALADDR, sizeof (char*), (BYTE*)VarAddr);
    Esize = EncodeEvent(Eh, Esize, ET_VALUE, sizeof (ObjValue), (BYTE*)VarValue);
    DynTrace(Eh, Esize, Tk);

    return;
}

static inline void OpCodeProc (PyFrameObject *frame, unsigned opcode, unsigned oparg, set <string> *BVs)
{
    if (!HAS_ARG(opcode))
    {
        return;
    }

    DEBUG_PRINT("\t > OPCODE[%d-%d]: %s ", opcode, oparg, Op2Name(opcode).c_str());
    PyObject *co_names = frame->f_code->co_names;
    PyObject *co_varnames = frame->f_code->co_varnames;

    Py_ssize_t CoSize = Py_SIZE (co_names);
    Py_ssize_t CoVarSize = Py_SIZE (co_varnames);

    PyObject *UseName = NULL;
    PyObject *UseVal  = NULL;

    ObjValue OV = {0};
    
    switch (opcode)
    {
        case COMPARE_OP:
        {       
            assert (frame->f_stacktop - frame->f_valuestack >= 2);
    
            PyObject* left = frame->f_stacktop[-2];
            PyObject* right = frame->f_stacktop[-1];

            DEBUG_PRINT ("left = %p, right = %p ", left, right);
            GetValue(left, &OV);
            GetValue(right, &OV);
            cout<<endl;
            break;
        }
        case STORE_FAST:
        {
            /* STORE_FAST namei -> pops the stack and stores into co_names[namei] */
            assert (frame->f_stacktop - frame->f_valuestack >= 1);

            UseName = PyTuple_GET_ITEM (co_varnames, oparg);
            const char* StrUseName = PyUnicode_AsUTF8(UseName);
            if (BVs->find (StrUseName) != BVs->end ())
            {
                UseVal  = frame->f_stacktop[-1];
                DEBUG_PRINT ("Name = %s, Ov = %p ", StrUseName, UseVal);           
                GetValue(UseVal, &OV);

                StartTracing (StrUseName, UseVal, &OV, STORE_FAST);                
            }
            DEBUG_PRINT ("\r\n");
            break;
        }
        case STORE_NAME:
        {
            /* STORE_NAME namei -> pops the stack and stores into co_names[namei] */
            assert (frame->f_stacktop - frame->f_valuestack >= 1);

            UseName = PyTuple_GET_ITEM (co_names, oparg);
            const char* StrUseName = PyUnicode_AsUTF8(UseName);
            if (BVs->find (StrUseName) != BVs->end ())
            {
                UseVal  = frame->f_stacktop[-1];
                DEBUG_PRINT ("Name = %s, Ov = %p ", StrUseName, UseVal);
                GetValue(UseVal, &OV);

                StartTracing (StrUseName, UseVal, &OV, STORE_NAME); 
            }
            DEBUG_PRINT ("\r\n");
            break;
        }
        case STORE_GLOBAL:
        {
            /* STORE_GLOBAL namei -> pops the stack and stores into co_names[namei] */
            assert (frame->f_stacktop - frame->f_valuestack >= 1);

            UseName = PyTuple_GET_ITEM (co_names, oparg);
            const char* StrUseName = PyUnicode_AsUTF8(UseName);
            if (BVs->find (StrUseName) != BVs->end ())
            {
                UseVal  = frame->f_stacktop[-1];
                GetValue(UseVal, &OV);

                StartTracing (StrUseName, UseVal, &OV, STORE_GLOBAL); 
            }
            DEBUG_PRINT ("\r\n");
            break;
        }
        case STORE_DEREF:
        {
            cout<<"Unsupported Opcode!!!!\r\n";
            assert (0);
            break;
        }
        case LOAD_FAST:
        {
            /* LOAD_FAST valnum -> push co_varnames[valnum] (frame->f_localsplus[oparg]) onto stack */
            UseName = PyTuple_GET_ITEM (co_varnames, oparg);
            UseVal  = frame->f_localsplus[oparg];
            DEBUG_PRINT ("Name = %s, Ov = %p ", PyUnicode_AsUTF8(UseName), UseVal);
            GetValue(UseVal, &OV);
            cout<<endl;
            break;
        }
        case LOAD_NAME:
        {
            /* LOAD_NAME namei -> push co_names[namei] onto stack */
            UseName = PyTuple_GET_ITEM (co_names, oparg);
            DEBUG_PRINT ("Name = %s ", PyUnicode_AsUTF8(UseName));
            if (PyDict_CheckExact(frame->f_locals)) 
            {
                UseVal  = PyDict_GetItemWithError(frame->f_locals, UseName);
            }
            else
            {
                UseVal = PyObject_GetItem(frame->f_locals, UseName);
            }

            if (UseVal != NULL) 
            {
                GetValue(UseVal, &OV);
            }
                
            cout<<endl;
            break;
        }
        case LOAD_GLOBAL:
        {
            /* LOAD_GLOBAL namei -> push co_names[namei] onto stack */
            //UseName = PyTuple_GET_ITEM (co_names, oparg);
            /* pass the global variables */            
            break;
        }
        case LOAD_DEREF:
        {
            cout<<"Unsupported Opcode!!!!\r\n";
            assert (0);
            break;
        }
        case CALL_FUNCTION:
        {
            break;
        }
        default:
        {
            break;
        }
    }

    cout<<endl;
    return;
}

int Tracer (PyObject *obj, PyFrameObject *frame, int what, PyObject *arg)
{   
    PyCodeObject *f_code  = frame->f_code;

    string FileName = BaseName(PyUnicode_AsUTF8(f_code->co_filename));
    if (!IsRegModule (FileName))
    {
        return 0;
    }
    const char* FuncName = PyUnicode_AsUTF8(f_code->co_name);
  
    set <string> *BVs = BvSet.GetBvSet (FileName, FuncName);
    if (BVs == NULL)
    {
        return 0;
    }
    DEBUG_PRINT ("%s : %s : %d --- length(BVs)-> %u ", FileName.c_str(), FuncName, frame->f_lineno, (unsigned)BVs->size ());

    
    // enable PyTrace_OPCODE
    frame->f_trace_opcodes = true;     
    //ShowVariables (co_varnames);
 
    switch(what)
    {
        case PyTrace_LINE:
        {
            DEBUG_PRINT("PyTrace_LINE:%d\n", what);
            break;
        }
        case PyTrace_CALL:
        {
            DEBUG_PRINT("PyTrace_CALL:%d, frame->f_localsplus = %p\n", what, frame->f_localsplus);
            break;
        }
        case PyTrace_EXCEPTION:
        {
            DEBUG_PRINT("PyTrace_EXCEPTION:%d\n", what);
            break;
        }
        case PyTrace_RETURN:
        {
            DEBUG_PRINT("PyTrace_RETURN:%d\n", what);
            break;
        }
        case PyTrace_OPCODE:
        {
            unsigned opcode = (unsigned char)PyBytes_AsString(f_code->co_code)[frame->f_lasti];
            unsigned oparg  = (unsigned char)PyBytes_AsString(f_code->co_code)[frame->f_lasti+1];
            DEBUG_PRINT("PyTrace_OPCODE:%d[%u|%u]\n", what, opcode, oparg);
            OpCodeProc (frame, opcode, oparg, BVs);
            break;
        }
        case PyTrace_C_CALL:
        {
            DEBUG_PRINT("PyTrace_C_CALL:%d\n", what);
            break;
        }
        case PyTrace_C_EXCEPTION:
        {
            DEBUG_PRINT("PyTrace_C_EXCEPTION:%d\n", what);
            break;
        }
        case PyTrace_C_RETURN:
        {
            DEBUG_PRINT("PyTrace_C_RETURN:%d\n", what);
            break;
        }
        default:
        {
            DEBUG_PRINT("default: %d\n", what);
            break;
        }
    }
    
    return 0;
}


}  
