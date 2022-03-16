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


static inline void TraceOpCode(PyFrameObject *frame, int what, PRT_function* Rtf)
{
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


static inline void TraceLine(PyFrameObject *frame, int what, PRT_function* Rtf)
{
    frame->f_trace_lines = true;
    printf ("\t[TraceLine][File:%u]Line:%u \r\n", Rtf->m_Idx, frame->f_lineno);
}

static inline void TraceSAI(PyFrameObject *frame, int what, PRT_function* Rtf)
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
