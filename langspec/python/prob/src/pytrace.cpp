#include "pytrace.h"
#include "op_code.h"
#include "prob_rt.h"
#include "DynTrace.h"
#include <cstddef>
#include <set>

#ifdef __cplusplus
extern "C" {
#endif

PyObject *PyEval_GetLocals(void);

#ifdef __cplusplus
}
#endif



namespace pyprob {

using namespace std;

static PRT __Prt;

void PyInit(string PySummary) 
{
    /* load all branch variables for each function */
    BV_set *BvSet = &__Prt.BvSet;
    unsigned BlockNum = BvSet->LoadPySummary(PySummary);

    /* Init tracing: shared memory ALF++, etc. */
    int FinalLoc = DynTraceInit (BlockNum);
    PY_PRINT (">>>>>>>>Get FinalLoc = %d before InitRtfs of python [%u]\r\n", FinalLoc, BlockNum);

    /* Init Rtfs */
    __Prt.InitRtfs(FinalLoc);
    PY_PRINT (">>>>>>>>Get FinalLoc = %d after InitRtfs of python [%u]\r\n", FinalLoc, BlockNum);

    return;
}


static inline string BaseName(string const &Path)
{
    return Path.substr(Path.find_last_of("/") + 1);
}


static inline void TraceOpCode(PyFrameObject *frame, int what, PRT_file* Rtf)
{
    frame->f_trace_opcodes = true;

    PyCodeObject *f_code  = frame->f_code;    
    unsigned opcode = (unsigned char)PyBytes_AsString(f_code->co_code)[frame->f_lasti];
    if (opcode != COMPARE_OP || frame->f_stacktop - frame->f_valuestack < 2)
    {
        return;
    }
    
    //unsigned oparg  = (unsigned char)PyBytes_AsString(f_code->co_code)[frame->f_lasti+1];
    if (!HAS_ARG(opcode))
    {
        return;
    }

    PyObject* LOp = frame->f_stacktop[-2];
    PyObject* ROp = frame->f_stacktop[-1];
    if (!PyLong_Check (LOp) || !PyLong_Check (ROp))
    {
        return;
    }

    ObjValue OV = {0};
    OV.Type   = VT_LONG;
    OV.Attr   = 0;
    OV.Length = sizeof(OV.Value);
    OV.Value  = PyLong_AsLong(LOp);
    PY_PRINT ("\t[TraceOpCode] > [Size:%u] [T: LONG, A:%u L: %u, V:%lx] \r\n", OV.Length, OV.Attr, OV.Length, OV.Value);

    return;
}

static inline const char* PyTypeInfo (PyObject *PyObj)
{
    PyTypeObject* type = PyObj->ob_type;
    return type->tp_name;
}


static inline PyObject* GetVarObj (PyFrameObject *frame, string VarName)
{
    PyObject *co_names    = frame->f_code->co_names;
    PyObject *co_varnames = frame->f_code->co_varnames;

    int VarNum = PyTuple_GET_SIZE(co_varnames);
    if (VarNum != 0)
    {
        for (int i = 0; i < VarNum; i++)
        {
            PyObject *ObjVname = PyTuple_GET_ITEM(co_varnames, i);
            if (PyUnicode_AsUTF8(ObjVname) == VarName)
            {
                return ObjVname;
            }
        }
    }

    VarNum = PyTuple_GET_SIZE(co_names);
    if (VarNum != 0)
    {
        for (int i = 0; i < VarNum; i++)
        {
            PyObject *ObjVname = PyTuple_GET_ITEM(co_names, i);
            if (PyUnicode_AsUTF8(ObjVname) == VarName)
            {
                return ObjVname;
            }
        }
    }

    return NULL;
}

static inline void TraceLine(PyFrameObject *frame, int what, PRT_file* Rtf)
{
    frame->f_trace_lines = true;

    BVar *BV = Rtf->RetrivBrVarKey(frame->f_lineno);
    if (BV == NULL)
    {
        return;
    }

    PyObject *f_locals = PyEval_GetLocals ();
    if (!PyDict_Check (f_locals))
    {
        return;
    }
    
    PyObject *VarName = GetVarObj (frame, BV->m_Name);
    if (VarName == NULL)
    {
        return;
    }

    PyObject *ObjBrVar = PyDict_GetItemWithError(f_locals, VarName);
    if (ObjBrVar == NULL)
    {
        return;
    }

    unsigned Value = PyLong_AsLong(ObjBrVar);
    DynTraceD32 (0, BV->m_Key, Value);
    PY_PRINT ("\t@@@ [TraceLine][File:%s]Line:%u, Var:%s:%u:%u\r\n", Rtf->m_FileName.c_str(), frame->f_lineno, BV->m_Name.c_str(), BV->m_Key, Value);
    return;
}


static inline void TraceSAI(PyFrameObject *frame, int what, PRT_file* Rtf)
{
    switch (what)
    {
        case PyTrace_OPCODE:
        {
            TraceOpCode (frame, what, Rtf);
            break;
        }
        case PyTrace_LINE:
        {
            TraceLine (frame, what, Rtf);
            break;
        }
        default:
        {
            return;
        }
    }

    return;
}


static inline void InjectCov(PyFrameObject *frame, PRT_file* Rtf) 
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

    #ifdef __DEBUG__
    const char* FuncName = PyUnicode_AsUTF8(f_code->co_name);
    #endif

    /* init runtime for current function */
    PRT_file* Rtf = __Prt.GetRtf (FileName, frame->f_lineno);
    if (Rtf == NULL)
    {
        PY_PRINT ("@@@ Retrieve %s fail \r\n", FileName.c_str());
        return 0;
    }
    
    PY_PRINT ("@@@ %s : %s :[%d] %d --- length(BVs)-> %u, Rtf[%p] \r\n", 
              FileName.c_str(), FuncName, Rtf->m_CurBB, frame->f_lineno, (unsigned)Rtf->m_BrVars->size(), Rtf);

#ifdef _PROB_DATA_
    TraceSAI (frame, what, Rtf);
#endif

    InjectCov (frame, Rtf);
    return 0;
}


}  
