#include "pytrace.h"
#include "op_code.h"
#include "prob_rt.h"
#include "DynTrace.h"
#include <cstddef>
#include <set>


namespace pyprob {

using namespace std;

static PRT __Prt;

void PyInit(string BrValXml) 
{
    /* load all branch variables for each function */
    BV_set *BvSet = &__Prt.BvSet;
    BvSet->LoadBrVals(BrValXml);

    /* Init tracing: shared memory ALF++, etc. */
    int FinalLoc = DynTraceInit (BvSet->m_Branchs);

    /* Init Rtfs */
    __Prt.InitRtfs(FinalLoc);
    PY_PRINT (">>>>>>>>Get FinalLoc = %d after InitRtfs of python\r\n", FinalLoc);
    
    return;
}


static inline string BaseName(string const &Path)
{
    return Path.substr(Path.find_last_of("/") + 1);
}


static inline void GetValue (PyObject *Var, ObjValue *OV)
{
    if (PyLong_Check (Var))
    {
        OV->Type   = VT_LONG;
        OV->Attr   = 0;
        OV->Length = sizeof(OV->Value);
        OV->Value  = PyLong_AsLong(Var);
        PY_PRINT ("\t > [Size:%u] [T: LONG, A:%u L: %u, V:%lx] \r\n", OV->Length, OV->Attr, OV->Length, OV->Value);
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
            for (unsigned off = 0; off < sizeof(OV->Value); off++)
            {
                Value[off] = UcVar[off * Scale];
            }
            OV->Length = sizeof(OV->Value);
        }
        PY_PRINT ("\t > [Size:%u] Unicode, Var:%lx -> %s \r\n", OV->Length, OV->Value, UcVar);
    }
    else if (PyTuple_Check (Var))
    {
        OV->Type   = VT_SET;
        OV->Attr   = 0;    
        OV->Length = (unsigned short)Py_SIZE(Var);
        
        PY_PRINT ("\t > [Size:%u] Tuple, Var:%lx  \r\n", OV->Length, OV->Value);
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
        PY_PRINT ("\t > [Size:%u] List, Var:%lx  \r\n", OV->Length, OV->Value);
    }
    else if (PyDict_Check (Var))
    {
        OV->Type   = VT_DICT;
        OV->Attr   = 0;    
        OV->Length = (unsigned short)Py_SIZE(Var);
        
        PY_PRINT ("\t > [Size:%u] Dict, Var:%lx  \r\n", OV->Length, OV->Value);
    }
    else if (PyBytes_Check (Var))
    {
        OV->Type   = VT_STRING;
        OV->Attr   = 0;    
        OV->Length = (unsigned short)Py_SIZE(Var);
        PY_PRINT ("\t > [Size:%u] Bytes, Var:%lx  \r\n", OV->Length, OV->Value);
    }
    else if (Var == Py_None)
    {
        PY_PRINT ("\t > NoneType, Var:%p  \r\n", Var);
    }
    else
    {
        PY_PRINT ("\t > Other:%s, Var:%lx  \r\n", Var->ob_type->tp_name, OV->Value);
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

static inline void TracingDefUse (const char* VarName, PyObject *VarAddr, ObjValue *VarValue, unsigned TrcKey)
{
    EVENT_HANDLE Eh = AllocEvent();
    assert (Eh != NULL);

    unsigned Esize = 0;
    Esize = EncodeEvent(Eh, Esize, ET_VALNAME, strlen(VarName), (BYTE*)VarName);
    Esize = EncodeEvent(Eh, Esize, ET_VALADDR, sizeof (char*), (BYTE*)VarAddr);
    Esize = EncodeEvent(Eh, Esize, ET_VALUE, sizeof (ObjValue), (BYTE*)VarValue);
    DynTrace(Eh, Esize, TrcKey);

    return;
}

static inline void InjectOpCode (PyFrameObject *frame, PRT_function* Rtf)
{
    PyCodeObject *f_code  = frame->f_code;
    
    unsigned opcode = (unsigned char)PyBytes_AsString(f_code->co_code)[frame->f_lasti];
    unsigned oparg  = (unsigned char)PyBytes_AsString(f_code->co_code)[frame->f_lasti+1];

    if (!HAS_ARG(opcode))
    {
        return;
    }

    PY_PRINT("\t > OPCODE[%d-%d]: %s \r\n", opcode, oparg, Op2Name(opcode).c_str());

    set <string> *BVs = Rtf->m_BrVals;
    PyObject *co_names = f_code->co_names;
    PyObject *co_varnames = f_code->co_varnames;

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

            PY_PRINT ("\t > left = %p, right = %p \r\n", left, right);
            GetValue(left, &OV);
            GetValue(right, &OV);
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
                PY_PRINT ("\t > Name = %s, Ov = %p \r\n", StrUseName, UseVal);           
                GetValue(UseVal, &OV);

                TracingDefUse (StrUseName, UseVal, &OV, Rtf->m_CurBB);                
            }
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
                PY_PRINT ("\t > Name = %s, Ov = %p \r\n", StrUseName, UseVal);
                GetValue(UseVal, &OV);

                TracingDefUse (StrUseName, UseVal, &OV, Rtf->m_CurBB); 
            }
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

                TracingDefUse (StrUseName, UseVal, &OV, Rtf->m_CurBB); 
            }
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
            PY_PRINT ("\t > Name = %s, Ov = %p \r\n", PyUnicode_AsUTF8(UseName), UseVal);
            GetValue(UseVal, &OV);
            break;
        }
        case LOAD_NAME:
        {
            /* LOAD_NAME namei -> push co_names[namei] onto stack */
            UseName = PyTuple_GET_ITEM (co_names, oparg);
            PY_PRINT ("\t > Name = %s \r\n", PyUnicode_AsUTF8(UseName));
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

    return;
}


static inline void InjectCov(PyFrameObject *frame, PRT_function* Rtf) 
{
    PY_PRINT("InjectCov: [PreBB : CurBB]  = [%d : %d] \r\n", Rtf->m_PreBB, Rtf->m_CurBB);
    if (Rtf->m_PreBB == 0)
    {
        DynTrace (NULL, 0, Rtf->m_CurBB);
        return;
    }
    else
    {
        if (Rtf->m_PreBB != Rtf->m_CurBB)
        {
            DynTrace (NULL, 0, Rtf->m_CurBB);
            return;
        }
    }  

    PY_PRINT("InjectCov: Ignore current block [%d]... \r\n", Rtf->m_CurBB);
    return;
}


int Tracer (PyObject *obj, PyFrameObject *frame, int what, PyObject *arg)
{   
    PyCodeObject *f_code  = frame->f_code;

    string FileName = BaseName(PyUnicode_AsUTF8(f_code->co_filename));
    const char* FuncName = PyUnicode_AsUTF8(f_code->co_name);

    //PY_PRINT ("@@@ %s : %s: %d\r\n", FileName.c_str(), FuncName, frame->f_lineno);
    
    int FIdx = __Prt.BvSet.GetFIdx (FileName, FuncName);
    if (FIdx == 0)
    {
        return 0;
    }

    /* init runtime for current function */
    PRT_function* Rtf = __Prt.GetRtf (FIdx, frame->f_lineno);
    PY_PRINT ("@@@ %s : [%u]%s :[%d] %d --- length(BVs)-> %u, Rtf[%p] \r\n", 
              FileName.c_str(), FIdx, FuncName, Rtf->m_CurBB, frame->f_lineno, (unsigned)Rtf->m_BrVals->size(), Rtf);
    
    // enable PyTrace_OPCODE
    frame->f_trace_opcodes = true;     
    //ShowVariables (co_varnames);

    switch(what)
    {
        case PyTrace_LINE:
        {
            PY_PRINT("PyTrace_LINE:%d\n", what);
            break;
        }
        case PyTrace_CALL:
        {
            PY_PRINT("PyTrace_CALL:%d, frame->f_localsplus = %p\n", what, frame->f_localsplus);
            break;
        }
        case PyTrace_EXCEPTION:
        {
            PY_PRINT("PyTrace_EXCEPTION:%d\n", what);
            break;
        }
        case PyTrace_RETURN:
        {
            PY_PRINT("PyTrace_RETURN:%d\n", what);
            break;
        }
        case PyTrace_OPCODE:
        {
            PY_PRINT("PyTrace_OPCODE:%d\n", what);
            InjectOpCode (frame, Rtf);
            break;
        }
        case PyTrace_C_CALL:
        {
            PY_PRINT("PyTrace_C_CALL:%d\n", what);
            break;
        }
        case PyTrace_C_EXCEPTION:
        {
            PY_PRINT("PyTrace_C_EXCEPTION:%d\n", what);
            break;
        }
        case PyTrace_C_RETURN:
        {
            PY_PRINT("PyTrace_C_RETURN:%d\n", what);
            break;
        }
        default:
        {
            PY_PRINT("default: %d\n", what);
            break;
        }
    }

    InjectCov (frame, Rtf);
    return 0;
}


}  
