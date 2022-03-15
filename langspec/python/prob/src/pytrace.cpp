#include "pytrace.h"
#include "op_code.h"
#include "prob_rt.h"
#include "DynTrace.h"
#include <cstddef>
#include <set>


namespace pyprob {

using namespace std;

static PRT __Prt;

void PyInit(string PySummary) 
{
    /* load all branch variables for each function */
    BV_set *BvSet = &__Prt.BvSet;
    BvSet->LoadPySummary(PySummary);

    /* Init tracing: shared memory ALF++, etc. */
    int FinalLoc = DynTraceInit (BvSet->m_Branchs);
    PY_PRINT (">>>>>>>>Get FinalLoc = %d before InitRtfs of python\r\n", FinalLoc);

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
    EHANDLE Eh = AllocEvent();
    assert (Eh != NULL);

    unsigned Esize = 0;
    Esize = EncodeEvent(Eh, Esize, ET_VALNAME, strlen(VarName), (BYTE*)VarName);
    Esize = EncodeEvent(Eh, Esize, ET_VALADDR, sizeof (char*), (BYTE*)VarAddr);
    Esize = EncodeEvent(Eh, Esize, ET_VALUE, sizeof (ObjValue), (BYTE*)VarValue);

    return;
}

static inline void TraceSAI(PyFrameObject *frame, int what, PRT_function* Rtf)
{
    if (what != PyTrace_OPCODE)
    {
        return;
    }
    frame->f_trace_opcodes = true;

    PyCodeObject *f_code  = frame->f_code;    
    unsigned opcode = (unsigned char)PyBytes_AsString(f_code->co_code)[frame->f_lasti];
    if (opcode != COMPARE_OP || frame->f_stacktop - frame->f_valuestack < 2)
    {
        return;
    }
    
    unsigned oparg  = (unsigned char)PyBytes_AsString(f_code->co_code)[frame->f_lasti+1];
    if (!HAS_ARG(opcode))
    {
        return;
    }

    ObjValue OV = {0};
    PyObject* left = frame->f_stacktop[-2];
    PyObject* right = frame->f_stacktop[-1];
    printf ("\t > left = %p, right = %p \r\n", left, right);
    
    GetValue(left, &OV);
    GetValue(right, &OV);

    return;
}


static inline void InjectCov(PyFrameObject *frame, PRT_function* Rtf) 
{
    PY_PRINT("InjectCov: [PreBB : CurBB]  = [%d : %d] \r\n", Rtf->m_PreBB, Rtf->m_CurBB);
    if (Rtf->m_PreBB == 0)
    {
        DynTracePCG(Rtf->m_CurBB);
        return;
    }
    else
    {
        if (Rtf->m_PreBB != Rtf->m_CurBB)
        {
            DynTracePCG (Rtf->m_CurBB);
            return;
        }
    }  

    PY_PRINT("InjectCov: Ignore current block [%d]... \r\n", Rtf->m_CurBB);
    return;
}


int Tracer (PyObject *obj, PyFrameObject *frame, int what, PyObject *arg)
{
    if (!__Prt.m_InitOkay)
    {
        return 0;
    }
    
    PyCodeObject *f_code  = frame->f_code;

    string FileName = BaseName(PyUnicode_AsUTF8(f_code->co_filename));
    const char* FuncName = PyUnicode_AsUTF8(f_code->co_name);

    //PY_PRINT ("@@@ %s : %s: %d\r\n", FileName.c_str(), FuncName, frame->f_lineno);
    
    int FIdx = __Prt.BvSet.GetFIdx (FileName, FuncName, frame->f_lineno);
    if (FIdx == 0)
    {
        return 0;
    }

    /* init runtime for current function */
    PRT_function* Rtf = __Prt.GetRtf (FIdx, frame->f_lineno);
    PY_PRINT ("@@@ %s : [%u]%s :[%d] %d --- length(BVs)-> %u, Rtf[%p] \r\n", 
              FileName.c_str(), FIdx, FuncName, Rtf->m_CurBB, frame->f_lineno, (unsigned)Rtf->m_BrVals->size(), Rtf);

#ifdef _PROB_DATA_
    TraceSAI (frame, what, Rtf);
#endif

    InjectCov (frame, Rtf);
    return 0;
}


}  
