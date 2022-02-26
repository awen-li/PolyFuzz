//===-- SanitizerCoverage.cpp - coverage instrumentation for sanitizers ---===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Coverage instrumentation done on LLVM IR level, works with Sanitizers.
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Instrumentation/SanitizerCoverage.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/EHPersonalities.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Mangler.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Type.h"
#include "llvm/InitializePasses.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/SpecialCaseList.h"
#if LLVM_MAJOR > 10 || (LLVM_MAJOR == 10 && LLVM_MINOR > 0)
  #include "llvm/Support/VirtualFileSystem.h"
#endif
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include "config.h"
#include "debug.h"
#include "afl-llvm-common.h"


#define DB_PRINT(format, ...) if (debug) printf("@@@ Wen -> " format, ##__VA_ARGS__)
#define DB_SHOWINST(Idx, Inst) if (debug) errs ()<<Idx<<": "<<Inst<<"\r\n";


using namespace llvm;
using namespace std;

#define DEBUG_TYPE "sancov"

const char SanCovTracePCIndirName[] = "__sanitizer_cov_trace_pc_indir";
const char SanCovTracePCName[] = "__sanitizer_cov_trace_pc";
const char SanCovTraceCmp1[] = "__sanitizer_cov_trace_cmp1";
const char SanCovTraceCmp2[] = "__sanitizer_cov_trace_cmp2";
const char SanCovTraceCmp4[] = "__sanitizer_cov_trace_cmp4";
const char SanCovTraceCmp8[] = "__sanitizer_cov_trace_cmp8";
const char SanCovTraceConstCmp1[] = "__sanitizer_cov_trace_const_cmp1";
const char SanCovTraceConstCmp2[] = "__sanitizer_cov_trace_const_cmp2";
const char SanCovTraceConstCmp4[] = "__sanitizer_cov_trace_const_cmp4";
const char SanCovTraceConstCmp8[] = "__sanitizer_cov_trace_const_cmp8";
const char SanCovTraceDiv4[] = "__sanitizer_cov_trace_div4";
const char SanCovTraceDiv8[] = "__sanitizer_cov_trace_div8";
const char SanCovTraceGep[] = "__sanitizer_cov_trace_gep";
const char SanCovTraceSwitchName[] = "__sanitizer_cov_trace_switch";
const char SanCovModuleCtorTracePcGuardName[] =
    "sancov.module_ctor_trace_pc_guard";
const char SanCovModuleCtor8bitCountersName[] =
    "sancov.module_ctor_8bit_counters";
const char SanCovModuleCtorBoolFlagName[] = "sancov.module_ctor_bool_flag";
static const uint64_t SanCtorAndDtorPriority = 2;

const char SanCovTracePCGuardName[] = "__sanitizer_cov_trace_pc_guard";

const char SanCovTracePCGuardInitName[] = "__sanitizer_cov_trace_pc_guard_init";
const char SanCov8bitCountersInitName[] = "__sanitizer_cov_8bit_counters_init";
const char SanCovBoolFlagInitName[] = "__sanitizer_cov_bool_flag_init";
const char SanCovPCsInitName[] = "__sanitizer_cov_pcs_init";

const char SanCovGuardsSectionName[] = "sancov_guards";
const char SanCovCountersSectionName[] = "sancov_cntrs";
const char SanCovBoolFlagSectionName[] = "sancov_bools";
const char SanCovPCsSectionName[] = "sancov_pcs";

const char SanCovLowestStackName[] = "__sancov_lowest_stack";

static const char *skip_nozero;
static const char *use_threadsafe_counters;

namespace {

SanitizerCoverageOptions OverrideFromCL(SanitizerCoverageOptions Options) {

    // Sets CoverageType and IndirectCalls.
    // SanitizerCoverageOptions CLOpts = getOptions(ClCoverageLevel);
    Options.CoverageType = SanitizerCoverageOptions::SCK_Edge;  // std::max(Options.CoverageType,
                                           // CLOpts.CoverageType);
    Options.IndirectCalls = false;           // CLOpts.IndirectCalls;
    Options.TraceCmp = false;                //|= ClCMPTracing;
    Options.TraceDiv = false;                //|= ClDIVTracing;
    Options.TraceGep = false;                //|= ClGEPTracing;
    Options.TracePC = false;                 //|= ClTracePC;
    Options.TracePCGuard = true;             // |= ClTracePCGuard;
    Options.Inline8bitCounters = 0;          //|= ClInline8bitCounters;
    
    // Options.InlineBoolFlag = 0; //|= ClInlineBoolFlag;
    Options.PCTable = false;     //|= ClCreatePCTable;
    Options.NoPrune = false;     //|= !ClPruneBlocks;
    Options.StackDepth = false;  //|= ClStackDepth;
    
    if (!Options.TracePCGuard && !Options.TracePC &&
        !Options.Inline8bitCounters && !Options.StackDepth /*&&
        !Options.InlineBoolFlag*/){
        Options.TracePCGuard = true;  // TracePCGuard is default.
    }

    if (getenv("AFL_TRACECMP")) {
        Options.TraceCmp = true;
    }

    return Options;

}


class ModuleDuCov {

public:
    typedef set<Instruction*> T_InstSet;
    typedef set<Value*> T_ValueSet;

    ModuleDuCov (Module &M, Function *F) {
        CurFunc = F;

        CurM = &M;
        C = &(CurM->getContext());
        DL = &CurM->getDataLayout();
        
        Type *      VoidTy = Type::getVoidTy(*C);
        IRBuilder<> IRB(*C);
        Int64PtrTy = PointerType::getUnqual(IRB.getInt64Ty());
        Int32PtrTy = PointerType::getUnqual(IRB.getInt32Ty());
        Int8PtrTy = PointerType::getUnqual(IRB.getInt8Ty());
        Int1PtrTy = PointerType::getUnqual(IRB.getInt1Ty());
        Int64Ty = IRB.getInt64Ty();
        Int32Ty = IRB.getInt32Ty();
        Int16Ty = IRB.getInt16Ty();
        Int8Ty = IRB.getInt8Ty();
        Int1Ty = IRB.getInt1Ty();

        SanCovTracePCGuardDuMap[8] = CurM->getOrInsertFunction("__sanitizer_cov_trace_pc_guard_d8",   VoidTy, Int32PtrTy, Int32Ty, Int8Ty);
        SanCovTracePCGuardDuMap[16] = CurM->getOrInsertFunction("__sanitizer_cov_trace_pc_guard_d16", VoidTy, Int32PtrTy, Int32Ty, Int16Ty);
        SanCovTracePCGuardDuMap[32] = CurM->getOrInsertFunction("__sanitizer_cov_trace_pc_guard_d32", VoidTy, Int32PtrTy, Int32Ty, Int32Ty);
        SanCovTracePCGuardDuMap[64] = CurM->getOrInsertFunction("__sanitizer_cov_trace_pc_guard_d64", VoidTy, Int32PtrTy, Int32Ty, Int64Ty);

        TargetExitFunction = CurM->getOrInsertFunction("__sanitizer_cov_trace_pc_guard_target_exit", VoidTy);

        CmpWithConstNum    = 0;
        CmpWithIntConstNum = 0;
        CmpWithNoConstNum  = 0;
        CmpWithIntNoConstNum = 0;
    }

    ~ModuleDuCov () {

    }

    inline void InjectExit () {
        set<Instruction *> ExitInsts;
        
        /* return in main function */
        Function *mainFunc = CurM->getFunction("main");
        if (mainFunc != NULL) {

            BasicBlock &termbBlock = CurFunc->back();
            Instruction *retInst   = termbBlock.getTerminator();
            if (isa<ReturnInst>(retInst))
            {
                ExitInsts.insert (retInst);
            }
        }

        /* exit() in all functions */
        for (auto &BB : *CurFunc) 
        {    
            for (auto &IN : BB) 
            {
                Instruction *Inst = &IN;
                CallInst *Ci = dyn_cast<CallInst>(Inst);
                if (Ci == NULL)
                {
                    continue;
                }

                Function *CalledFunc = Ci->getCalledFunction();
                if (CalledFunc == NULL || !CalledFunc->hasName())
                {
                    continue;
                }
                
                if (CalledFunc->getName().str() == "exit") 
                {
                    ExitInsts.insert(Inst);
                }     
            }  
        }

        for (auto it = ExitInsts.begin(); it != ExitInsts.end(); ++it) 
        {
            Instruction *Inst = *it;
            CallInst::Create(TargetExitFunction, "", Inst);
        }

    }

    inline void SetInjected (Instruction *Inst) {
        InjectedInsts.insert (Inst);
    }

    inline bool IsInjected (Instruction *Inst) {
        auto It = InjectedInsts.find (Inst);
        if (It == InjectedInsts.end ()) {
            return false;
        }
        else {
            return true;
        }
    }

    inline Instruction* GetBBFirstInst (BasicBlock *BB) {
        auto It = BB2FirstInst.find (BB);
        if (It == BB2FirstInst.end ()) {
            return NULL;
        }
        
        return It->second;
    }

    inline unsigned Size ()
    {
        return (unsigned)BB2FirstInst.size ();
    }

    inline Instruction* GetInstrmInst (Instruction *BrDefInst)
    {
        auto It = BrDefInst2PosInst.find (BrDefInst);
        if (It == BrDefInst2PosInst.end ())
            return NULL;

        return It->second;
    }

    inline void DumpBrVals (unsigned Key, char* Type, unsigned Predict, Value *Val)
    {
        unsigned long ConstVal = 0;
        if (ConstantInt* CI = dyn_cast<ConstantInt>(Val)) {
            ConstVal = CI->getSExtValue();
        }
        else
        {
            if (ConstantData *CD = dyn_cast<ConstantData>(Val))
            {
                errs ()<<"Warning: Not IntConstant but ----> "<<*Val<<"\r\n";
            }
            else
            {
                ;
            }

            return;
        }

        FILE *F = fopen ("branch_vars.bv", "a+");
        assert (F != NULL);
        fprintf (F, "%u:%s:%u:%lu\r\n", Key, Type, Predict, ConstVal);
        fclose (F);
    }

    inline void CmpProc (Value* BrVal, ICmpInst::Predicate pred, Value* CmpVal)
    {
        unsigned Key = (unsigned)(unsigned long)BrVal;
        switch (pred)
        {
            case ICmpInst::FCMP_FALSE: /// = 1 < 0 0 0 1    True if ordered and equal
            case ICmpInst::FCMP_OEQ:   /// = 1 < 0 0 0 1    True if ordered and equal
            case ICmpInst::FCMP_OGT:   /// = 2,   ///< 0 0 1 0    True if ordered and greater than
            case ICmpInst::FCMP_OGE:   /// = 3,   ///< 0 0 1 1    True if ordered and greater than or equal
            case ICmpInst::FCMP_OLT:   /// = 4,   ///< 0 1 0 0    True if ordered and less than
            case ICmpInst::FCMP_OLE:   /// = 5,   ///< 0 1 0 1    True if ordered and less than or equal
            case ICmpInst::FCMP_ONE:   /// = 6,   ///< 0 1 1 0    True if ordered and operands are unequal
            case ICmpInst::FCMP_ORD:   /// = 7,   ///< 0 1 1 1    True if ordered (no nans)
            case ICmpInst::FCMP_UNO:   /// = 8,   ///< 1 0 0 0    True if unordered: isnan(X) | isnan(Y)
            case ICmpInst::FCMP_UEQ:   /// = 9,   ///< 1 0 0 1    True if unordered or equal
            case ICmpInst::FCMP_UGT:   /// = 10,  ///< 1 0 1 0    True if unordered or greater than
            case ICmpInst::FCMP_UGE:   /// = 11,  ///< 1 0 1 1    True if unordered, greater than, or equal
            case ICmpInst::FCMP_ULT:   /// = 12,  ///< 1 1 0 0    True if unordered or less than
            case ICmpInst::FCMP_ULE:   /// = 13,  ///< 1 1 0 1    True if unordered, less than, or equal
            case ICmpInst::FCMP_UNE:   /// = 14,  ///< 1 1 1 0    True if unordered or not equal
            case ICmpInst::FCMP_TRUE:  /// = 15, ///< 1 1 1 1    Always true (always folded)
            {
                break;
            }
            case ICmpInst::ICMP_EQ:    /// = 32,  ///< equal
            case ICmpInst::ICMP_NE:    /// = 33,  ///< not equal
            case ICmpInst::ICMP_UGT:   /// = 34, ///< unsigned greater than
            case ICmpInst::ICMP_UGE:   /// = 35, ///< unsigned greater or equal
            case ICmpInst::ICMP_ULT:   /// = 36, ///< unsigned less than
            case ICmpInst::ICMP_ULE:   /// = 37, ///< unsigned less or equal
            case ICmpInst::ICMP_SGT:   /// = 38, ///< signed greater than
            case ICmpInst::ICMP_SGE:   /// = 39, ///< signed greater or equal
            case ICmpInst::ICMP_SLT:   /// = 40, ///< signed less than
            case ICmpInst::ICMP_SLE:   /// = 41, ///< signed less or equal
            {
                DumpBrVals (Key, (char*)"CMP", pred, CmpVal);
                break;
            }
            default:
            {
                return;
            }
        }
    }

    inline void SwitchProc (Instruction *St)
    {
        unsigned Key = (unsigned)(unsigned long)St->getOperand(0);
        
        unsigned ix = 1;
        unsigned OpNum = St->getNumOperands ();
        while (ix < OpNum) 
        {
            Value *Use = St->getOperand(ix);

            DumpBrVals (Key, (char*)"SWITCH", 255, Use);
            ix++;
        }      
        return;
    }

    inline void CollectDus () {

        T_InstSet BrInstSet;
        T_ValueSet BrValueSet;

        /* 1. get ALL branch/switch instructions*/
        for (auto &BB : *CurFunc) 
        {    
            for (auto &IN : BB) 
            {
                Instruction *Inst = &IN;
                if (ICmpInst *CMP = dyn_cast<ICmpInst>(Inst)) {
                    BrInstSet.insert(Inst);
                }

                if (isa<SwitchInst>(Inst)) {
                    BrInstSet.insert(Inst);
                }
            }     
        }

        /* 2. extract variable from branch insts */
        for (auto It = BrInstSet.begin (); It != BrInstSet.end (); It++)
        {
            Instruction *Inst = *It;

            Value *BrVar = NULL;
            Value *BrConst = NULL;

            if (ICmpInst *CMP = dyn_cast<ICmpInst>(Inst)) {
                Value *VarL = Inst->getOperand(0);
                Value *VarR = Inst->getOperand(1);
                if (isa<Constant>(VarL) || isa<Constant>(VarR)) {            
                    if (isa<ConstantInt>(VarL)) {
                        BrConst = VarL;
                        BrVar   = VarR;
                    }
                    else {
                        BrConst = VarR;
                        BrVar   = VarL;             
                    }

                    CmpWithConstNum++;
                    if (!BrVar->getType()->isIntegerTy()) continue;
                    CmpWithIntConstNum++;
                    
                    CmpProc (BrVar, CMP->getPredicate (), BrConst);
                }
                else {
                    CmpWithNoConstNum++;
                    if (VarR->getType()->isIntegerTy())
                    {
                        CmpWithIntNoConstNum++;
                    }
                    continue;
                }
            }
            else {
                BrVar = Inst->getOperand(0);
                
                CmpWithConstNum++;               
                if (!BrVar->getType()->isIntegerTy()) continue;
                CmpWithIntConstNum++;
                
                SwitchProc (Inst);
            }

            BrValueSet.insert (BrVar);

            /* check use of formal arguments */
            for (auto It = CurFunc->arg_begin(); It != CurFunc->arg_end(); It++) {
                Value *Arg = &(*It);
                if (Arg == BrVar) {
                   BrDefInst2PosInst [Inst] = Inst;
                   BrInst2FormalUse[Inst] = BrVar;
                   errs ()<<"Use formal argument ---> "<<*Inst<<"\r\n";
                }
            }
        }

        /* 3. get DEF of branch variables */
        for (auto &BB : *CurFunc) 
        {
            Instruction *BrDefInst = NULL;
            for (auto &IN: BB) 
            {
                Instruction *Inst = &IN;

                /* LLVM instrument: before the next instruction */
                if (BrDefInst != NULL) {
                    BrDefInst2PosInst [BrDefInst] = Inst;
                    BrDefInst = NULL;
                }

                Value *Def = Inst;
                auto It = BrValueSet.find (Def);
                if (It == BrValueSet.end ()) continue;
                
                BrDefInst = Inst;
                errs ()<<"Brvariable DEF ----> "<<*BrDefInst<<"\r\n";
                
                BasicBlock *CurBB = &BB;
                if (BB2FirstInst.find (CurBB) == BB2FirstInst.end ()) {
                    BB2FirstInst [CurBB] = BrDefInst;
                }
            }               
        }

        DumpStatistic (&BrInstSet, CurFunc);
        printf("BrInstSet: %u, BrValueSet: %u, BasicBlock Num: %u\r\n", 
               (unsigned)BrInstSet.size(), (unsigned)BrValueSet.size(), (unsigned)BB2FirstInst.size());

        return;
    }

    inline void DumpStatistic (T_InstSet *BrInstSet, Function *F)
    {
        FILE *SF = fopen ("cmp_statistic.info", "a+");
        if (SF == NULL) return;

        fprintf (SF, "%s:%u:%u:%u:%u:%u\n", 
                 F->getName().data(), (unsigned)BrInstSet->size (),
                 CmpWithConstNum, CmpWithIntConstNum,
                 CmpWithNoConstNum, CmpWithIntNoConstNum);
        fclose (SF);
    }

    inline CallInst* InjectOne (IRBuilder<> &IRB, Value *Def, Value* GuardPtr=NULL) {

        uint64_t TypeSize = DL->getTypeStoreSizeInBits(Def->getType());
        auto It = SanCovTracePCGuardDuMap.find (TypeSize);
        if (It == SanCovTracePCGuardDuMap.end ())
            return NULL;

        if (GuardPtr == NULL) {   
            GuardPtr = ConstantPointerNull::get(cast<PointerType>(Int32PtrTy));
        }

        FunctionCallee TraceFunc = It->second;
        Value *KeyVal = ConstantInt::get(Int32Ty, (unsigned)(unsigned long)Def, false);       
        auto ValTy = Type::getIntNTy(*C, TypeSize);
        
        CallInst *Ci = IRB.CreateCall(TraceFunc, {GuardPtr, KeyVal, IRB.CreateIntCast(Def, ValTy, true)});
        return Ci;
    }

    inline void RunInject () {
        for (auto It = BrDefInst2PosInst.begin (); It != BrDefInst2PosInst.end (); It++) {
            Instruction *BrDefInst = It->first;
            Instruction *PosInst = It->second;
            
            if (IsInjected (PosInst)) continue;

            Value *Def = BrDefInst;
            if (BrDefInst == PosInst) {
                auto Itv = BrInst2FormalUse.find (BrDefInst);
                assert (Itv != BrInst2FormalUse.end ());
                Def = Itv->second;
            }

            IRBuilder<> IRB(PosInst);
            CallInst *CI = InjectOne (IRB, Def);
            if (CI != NULL)
            {
                CI->setCannotMerge();
                DB_SHOWINST (__LINE__, *CI);
            }
        }

        InjectExit ();
        return;
    }

private:
    Function *CurFunc;
    DenseMap<BasicBlock*, Instruction*> BB2FirstInst;
    DenseMap<Instruction*, Instruction*> BrDefInst2PosInst;
    DenseMap<Instruction*, Value*> BrInst2FormalUse;
    set<Instruction*> InjectedInsts;

    LLVMContext* C;
    const DataLayout *DL;
    Module *CurM;
    Type *IntptrTy, *IntptrPtrTy, *Int64Ty, *Int64PtrTy, *Int32Ty, *Int32PtrTy,
         *Int16Ty, *Int8Ty, *Int8PtrTy, *Int1Ty, *Int1PtrTy;

    DenseMap<int, FunctionCallee> SanCovTracePCGuardDuMap;
    FunctionCallee TargetExitFunction;

    unsigned CmpWithConstNum;
    unsigned CmpWithIntConstNum;
    
    unsigned CmpWithNoConstNum;
    unsigned CmpWithIntNoConstNum;
    
};

using DomTreeCallback = function_ref<const DominatorTree *(Function &F)>;
using PostDomTreeCallback = function_ref<const PostDominatorTree *(Function &F)>;

class ModuleSanitizerCoverage {

public:
    ModuleSanitizerCoverage(const SanitizerCoverageOptions &Options = SanitizerCoverageOptions()
#if LLVM_MAJOR > 10
                                        ,
                                        const SpecialCaseList *Allowlist = nullptr,
                                        const SpecialCaseList *Blocklist = nullptr
#endif
      ): Options(OverrideFromCL(Options)) {

    }

    bool instrumentModule(Module &M, DomTreeCallback DTCallback,
                                  PostDomTreeCallback PDTCallback);

private:
    void instrumentFunction(Function &F, DomTreeCallback DTCallback,
                                     PostDomTreeCallback PDTCallback);
    void InjectCoverageForIndirectCalls(Function &              F,
                                                       ArrayRef<Instruction *> IndirCalls);
    void InjectTraceForCmp(Function &F, ArrayRef<Instruction *> CmpTraceTargets);
    void InjectTraceForDiv(Function &                 F,
                                   ArrayRef<BinaryOperator *> DivTraceTargets);
    void InjectTraceForGep(Function &                    F,
                                   ArrayRef<GetElementPtrInst *> GepTraceTargets);
    void InjectTraceForSwitch(Function &              F,
                                        ArrayRef<Instruction *> SwitchTraceTargets);
    bool InjectCoverage(Function &F, ModuleDuCov &MDu, ArrayRef<BasicBlock *> AllBlocks, bool IsLeafFunc = true);
    GlobalVariable *CreateFunctionLocalArrayInSection(size_t    NumElements, Function &F, Type *Ty, const char *Section);

    GlobalVariable *CreatePCArray(Function &F, ArrayRef<BasicBlock *> AllBlocks);
    void CreateFunctionLocalArrays(Function &F, ArrayRef<BasicBlock *> AllBlocks, uint32_t special);
    void InjectCoverageAtBlock(Function &F, ModuleDuCov &MDu, BasicBlock &BB, size_t Idx, bool IsLeafFunc = true);
    Function *CreateInitCallsForSections(Module &M, const char *CtorName,
                                                      const char *InitFunctionName, Type *Ty,
                                                      const char *Section);
    std::pair<Value *, Value *> CreateSecStartEnd(Module &M, const char *Section, Type *Ty);

    void SetNoSanitizeMetadata(Instruction *I) {

        I->setMetadata(I->getModule()->getMDKindID("nosanitize"), MDNode::get(*C, None));

    }

    inline void InjectPrintf(IRBuilder<> &IRB, const char* FormatStr, Value* Target, size_t Tag)
    {
        Value *Format = IRB.CreateGlobalStringPtr(FormatStr);
        CallInst *CallPrintf = IRB.CreateCall(DbPrintf, {Format, Target});
        DB_SHOWINST (Tag, *CallPrintf);
        return;
    }

    inline void InjectCovByInstruction (IRBuilder<> &IRB, size_t Idx)
    {
        /* Get CurLoc */
        Value *AddPtr   = IRB.CreateAdd(IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                                        ConstantInt::get(IntptrTy, Idx * 4));
        DB_SHOWINST (__LINE__, *AddPtr);
        Value *GuardPtr = IRB.CreateIntToPtr(AddPtr, Int32PtrTy);
        DB_SHOWINST (__LINE__, *GuardPtr);

        LoadInst *CurLoc = IRB.CreateLoad(GuardPtr);
        DB_SHOWINST (Idx, *CurLoc);

        InjectPrintf(IRB, "DbPrintf ->load from Array: %u\r\n", CurLoc, Idx);

        /* Load SHM pointer */
        LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
        DB_SHOWINST (Idx, *MapPtr);

        /* Load counter for CurLoc */
        Value *MapPtrIdx = IRB.CreateGEP(MapPtr, CurLoc);
        DB_SHOWINST (Idx, *MapPtrIdx);

        if (use_threadsafe_counters) {

            IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Add, MapPtrIdx, One,
#if LLVM_VERSION_MAJOR >= 13
                                llvm::MaybeAlign(1),
#endif
                                llvm::AtomicOrdering::Monotonic);

        } else {
            LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
            InjectPrintf(IRB, "DbPrintf ->load from shm: %u\r\n", Counter, Idx);
            
            /* Update bitmap */
            Value *Incr = IRB.CreateAdd(Counter, One);
            DB_SHOWINST (Idx, *Incr);
            
            if (skip_nozero == NULL) {

                auto cf = IRB.CreateICmpEQ(Incr, Zero);
                DB_SHOWINST (Idx, *cf);
                
                auto carry = IRB.CreateZExt(cf, Int8Ty);
                DB_SHOWINST (Idx, *carry);
                
                Incr = IRB.CreateAdd(Incr, carry);
                DB_SHOWINST (Idx, *Incr);
            }

            StoreInst *StInst = IRB.CreateStore(Incr, MapPtrIdx);
            assert (StInst != NULL);
            DB_SHOWINST (Idx, *StInst);
        }

        return;
    }

    inline void InjectCovByCallee (ModuleDuCov &MDu, IRBuilder<> &IRB, size_t Idx, Instruction *InjectDu=NULL)
    {
        Value *AddPtr   = IRB.CreateAdd(IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                                        ConstantInt::get(IntptrTy, Idx * 4));
        Value *GuardPtr = IRB.CreateIntToPtr(AddPtr, Int32PtrTy);

        CallInst* Ci;
        if (InjectDu == NULL) {
            Ci = IRB.CreateCall(SanCovTracePCGuard, GuardPtr);
        }
        else {
            Ci = MDu.InjectOne(IRB, InjectDu, GuardPtr);
            if (Ci == NULL)
                Ci = IRB.CreateCall(SanCovTracePCGuard, GuardPtr);
        }
        Ci->setCannotMerge();
        
        DB_SHOWINST (__LINE__, *Ci);
        
        return;
    }

    bool IsInjectByInst;
    bool IsBrDefUse;
    
    std::string     getSectionName(const std::string &Section) const;
    std::string     getSectionStart(const std::string &Section) const;
    std::string     getSectionEnd(const std::string &Section) const;
    FunctionCallee  SanCovTracePCIndir;
    FunctionCallee  SanCovTracePC, SanCovTracePCGuard;
    FunctionCallee  SanCovTraceCmpFunction[4];
    FunctionCallee  SanCovTraceConstCmpFunction[4];
    FunctionCallee  SanCovTraceDivFunction[2];
    FunctionCallee  SanCovTraceGepFunction;
    FunctionCallee  SanCovTraceSwitchFunction;
    FunctionCallee  DbPrintf;
    
    GlobalVariable *SanCovLowestStack;
    Type *IntptrTy, *IntptrPtrTy, *Int64Ty, *Int64PtrTy, *Int32Ty, *Int32PtrTy,
         *Int16Ty, *Int8Ty, *Int8PtrTy, *Int1Ty, *Int1PtrTy;
    Module *          CurModule;
    std::string       CurModuleUniqueId;
    Triple            TargetTriple;
    LLVMContext *     C;
    const DataLayout *DL;

    GlobalVariable *FunctionGuardArray;        // for trace-pc-guard.
    GlobalVariable *Function8bitCounterArray;  // for inline-8bit-counters.
    GlobalVariable *FunctionBoolArray;         // for inline-bool-flag.
    GlobalVariable *FunctionPCsArray;          // for pc-table.
    SmallVector<GlobalValue *, 20> GlobalsToAppendToUsed;
    SmallVector<GlobalValue *, 20> GlobalsToAppendToCompilerUsed;

    SanitizerCoverageOptions Options;

    uint32_t        instr = 0;
    GlobalVariable *AFLMapPtr = NULL;
    ConstantInt *   One = NULL;
    ConstantInt *   Zero = NULL;

};

class ModuleSanitizerCoverageLegacyPass : public ModulePass {

public:
    ModuleSanitizerCoverageLegacyPass(const SanitizerCoverageOptions &Options = SanitizerCoverageOptions()
#if LLVM_VERSION_MAJOR > 10
                                                       ,
                                                       const std::vector<std::string> &AllowlistFiles = std::vector<std::string>(),
                                                       const std::vector<std::string> &BlocklistFiles = std::vector<std::string>()
#endif
                                                      ): ModulePass(ID), Options(Options) {

        initializeModuleSanitizerCoverageLegacyPassPass(*PassRegistry::getPassRegistry());

    }

    bool runOnModule(Module &M) override {
        DB_PRINT ("@@@ <Wen> ======================== runOnModule -> %s ======================== \r\n", M.getName().data());
        ModuleSanitizerCoverage ModuleSancov(Options
#if LLVM_MAJOR > 10
                                             ,
                                             Allowlist.get(), Blocklist.get()
#endif
                                             );
        auto DTCallback = [this](Function &F) -> const DominatorTree * {

            return &this->getAnalysis<DominatorTreeWrapperPass>(F).getDomTree();

        };

        auto PDTCallback = [this](Function &F) -> const PostDominatorTree * {

            return &this->getAnalysis<PostDominatorTreeWrapperPass>(F).getPostDomTree();

        };

        return ModuleSancov.instrumentModule(M, DTCallback, PDTCallback);
    }

    static char ID;  // Pass identification, replacement for typeid
    StringRef   getPassName() const override {

        return "ModuleSanitizerCoverage";

    }

    void getAnalysisUsage(AnalysisUsage &AU) const override {

        AU.addRequired<DominatorTreeWrapperPass>();
        AU.addRequired<PostDominatorTreeWrapperPass>();

    }

private:
    SanitizerCoverageOptions Options;

    std::unique_ptr<SpecialCaseList> Allowlist;
    std::unique_ptr<SpecialCaseList> Blocklist;

};

}  // namespace

PreservedAnalyses ModuleSanitizerCoveragePass::run(Module &M, ModuleAnalysisManager &MAM) {

    ModuleSanitizerCoverage ModuleSancov(Options
#if LLVM_MAJOR > 10
                                         ,
                                         Allowlist.get(), Blocklist.get()
#endif
    );
    
    auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
    
    auto  DTCallback = [&FAM](Function &F) -> const DominatorTree * {
        return &FAM.getResult<DominatorTreeAnalysis>(F);
    };

    auto PDTCallback = [&FAM](Function &F) -> const PostDominatorTree * {
        return &FAM.getResult<PostDominatorTreeAnalysis>(F);
    };

    if (ModuleSancov.instrumentModule(M, DTCallback, PDTCallback))
        return PreservedAnalyses::none();
    
    return PreservedAnalyses::all();
}

std::pair<Value *, Value *> ModuleSanitizerCoverage::CreateSecStartEnd(Module &M, const char *Section, Type *Ty) {

    GlobalVariable *SecStart = new GlobalVariable(M, Ty->getPointerElementType(), false,
                                                  GlobalVariable::ExternalWeakLinkage, nullptr, getSectionStart(Section));
    SecStart->setVisibility(GlobalValue::HiddenVisibility);
  
    GlobalVariable *SecEnd = new GlobalVariable(M, Ty->getPointerElementType(), false,
                                                GlobalVariable::ExternalWeakLinkage, nullptr, getSectionEnd(Section));
    SecEnd->setVisibility(GlobalValue::HiddenVisibility);

    if (!TargetTriple.isOSBinFormatCOFF())
        return std::make_pair(SecStart, SecEnd);

    // Account for the fact that on windows-msvc __start_* symbols actually
    // point to a uint64_t before the start of the array.
    IRBuilder<> IRB(M.getContext());
    auto SecStartI8Ptr = IRB.CreatePointerCast(SecStart, Int8PtrTy);    
    auto GEP = IRB.CreateGEP(Int8Ty, SecStartI8Ptr, ConstantInt::get(IntptrTy, sizeof(uint64_t)));

    return std::make_pair(IRB.CreatePointerCast(GEP, Ty), SecEnd);
}

Function *ModuleSanitizerCoverage::CreateInitCallsForSections(Module &M, const char *CtorName, const char *InitFunctionName, 
                                                                           Type *Ty, const char *Section) {

    auto SecStartEnd = CreateSecStartEnd(M, Section, Ty);
    auto SecStart    = SecStartEnd.first;
    auto SecEnd      = SecStartEnd.second;
    Function *CtorFunc;
    
    std::tie(CtorFunc, std::ignore) = createSanitizerCtorAndInitFunctions(M, CtorName, InitFunctionName, {Ty, Ty}, {SecStart, SecEnd});
    assert(CtorFunc->getName() == CtorName);
    DB_SHOWINST(__LINE__, *CtorFunc);

    if (TargetTriple.supportsCOMDAT()) {
        // Use comdat to dedup CtorFunc.
        CtorFunc->setComdat(M.getOrInsertComdat(CtorName));
        appendToGlobalCtors(M, CtorFunc, SanCtorAndDtorPriority, CtorFunc);
    } else {

        appendToGlobalCtors(M, CtorFunc, SanCtorAndDtorPriority);
    }

    if (TargetTriple.isOSBinFormatCOFF()) {

        // In COFF files, if the contructors are set as COMDAT (they are because
        // COFF supports COMDAT) and the linker flag /OPT:REF (strip unreferenced
        // functions and data) is used, the constructors get stripped. To prevent
        // this, give the constructors weak ODR linkage and ensure the linker knows
        // to include the sancov constructor. This way the linker can deduplicate
        // the constructors but always leave one copy.
        CtorFunc->setLinkage(GlobalValue::WeakODRLinkage);
        appendToUsed(M, CtorFunc);
    }

    return CtorFunc;
}

bool ModuleSanitizerCoverage::instrumentModule(Module &M, DomTreeCallback DTCallback, PostDomTreeCallback PDTCallback) {

    setvbuf(stdout, NULL, _IONBF, 0);
    if (getenv("AFL_DEBUG")) debug = 1;

    if ((isatty(2) && !getenv("AFL_QUIET")) || debug) {
        SAYF(cCYA "SanitizerCoveragePCGUARD" VERSION cRST "\n");
    } else {  
        be_quiet = 1;
    }

    skip_nozero = getenv("AFL_LLVM_SKIP_NEVERZERO");
    use_threadsafe_counters = getenv("AFL_LLVM_THREADSAFE_INST");
    DB_PRINT("skip_nozero = %p, use_threadsafe_counters = %p \r\n", skip_nozero, use_threadsafe_counters);

    initInstrumentList();
    scanForDangerousFunctions(&M);

    
    DB_PRINT("SANCOV: covtype:%u indirect:%d stack:%d noprune:%d "\
              "traceCmp:%d traceDiv:%d traceGep:%d "\
              "createtable:%d tracepcguard:%d tracepc:%d\n",
              Options.CoverageType, 
              Options.IndirectCalls == true ? 1 : 0,
              Options.StackDepth == true ? 1 : 0, 
              Options.NoPrune == true ? 1 : 0,
              Options.TraceCmp == true ? 1 : 0,
              Options.TraceDiv == true ? 1 : 0,
              Options.TraceGep == true ? 1 : 0,
              Options.PCTable == true ? 1 : 0,
              Options.TracePCGuard == true ? 1 : 0,
              Options.TracePC == true ? 1 : 0);

    if (Options.CoverageType == SanitizerCoverageOptions::SCK_None) return false;
    
    C = &(M.getContext());
    DL = &M.getDataLayout();
    
    CurModule = &M;
    CurModuleUniqueId = getUniqueModuleId(CurModule);
    TargetTriple = Triple(M.getTargetTriple());
    FunctionGuardArray = nullptr;
    Function8bitCounterArray = nullptr;
    FunctionBoolArray = nullptr;
    FunctionPCsArray = nullptr;
    IntptrTy = Type::getIntNTy(*C, DL->getPointerSizeInBits());
    IntptrPtrTy = PointerType::getUnqual(IntptrTy);
    
    Type *      VoidTy = Type::getVoidTy(*C);
    IRBuilder<> IRB(*C);
    Int64PtrTy = PointerType::getUnqual(IRB.getInt64Ty());
    Int32PtrTy = PointerType::getUnqual(IRB.getInt32Ty());
    Int8PtrTy = PointerType::getUnqual(IRB.getInt8Ty());
    Int1PtrTy = PointerType::getUnqual(IRB.getInt1Ty());
    Int64Ty = IRB.getInt64Ty();
    Int32Ty = IRB.getInt32Ty();
    Int16Ty = IRB.getInt16Ty();
    Int8Ty = IRB.getInt8Ty();
    Int1Ty = IRB.getInt1Ty();
    LLVMContext &Ctx = M.getContext();
    
    IsInjectByInst = (bool)(getenv ("AFL_INJECT_BY_INST") != NULL);
    IsBrDefUse     = true;

    AFLMapPtr = new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                                   GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");
    One = ConstantInt::get(IntegerType::getInt8Ty(Ctx), 1);
    Zero = ConstantInt::get(IntegerType::getInt8Ty(Ctx), 0);

    SanCovTracePCIndir =  M.getOrInsertFunction(SanCovTracePCIndirName, VoidTy, IntptrTy);
    // Make sure smaller parameters are zero-extended to i64 if required by the
    // target ABI.
    AttributeList SanCovTraceCmpZeroExtAL;
    SanCovTraceCmpZeroExtAL = SanCovTraceCmpZeroExtAL.addParamAttribute(*C, 0, Attribute::ZExt);
    SanCovTraceCmpZeroExtAL = SanCovTraceCmpZeroExtAL.addParamAttribute(*C, 1, Attribute::ZExt);

    SanCovTraceCmpFunction[0] = M.getOrInsertFunction(SanCovTraceCmp1, SanCovTraceCmpZeroExtAL, VoidTy,
                                                      IRB.getInt8Ty(), IRB.getInt8Ty());
    SanCovTraceCmpFunction[1] = M.getOrInsertFunction(SanCovTraceCmp2, SanCovTraceCmpZeroExtAL, VoidTy,
                                                      IRB.getInt16Ty(), IRB.getInt16Ty());
    SanCovTraceCmpFunction[2] = M.getOrInsertFunction(SanCovTraceCmp4, SanCovTraceCmpZeroExtAL, VoidTy,
                                                      IRB.getInt32Ty(), IRB.getInt32Ty());
    SanCovTraceCmpFunction[3] = M.getOrInsertFunction(SanCovTraceCmp8, VoidTy, Int64Ty, Int64Ty);

    SanCovTraceConstCmpFunction[0] = M.getOrInsertFunction(SanCovTraceConstCmp1, SanCovTraceCmpZeroExtAL, VoidTy, Int8Ty, Int8Ty);
    SanCovTraceConstCmpFunction[1] = M.getOrInsertFunction(SanCovTraceConstCmp2, SanCovTraceCmpZeroExtAL, VoidTy, Int16Ty, Int16Ty);
    SanCovTraceConstCmpFunction[2] = M.getOrInsertFunction(SanCovTraceConstCmp4, SanCovTraceCmpZeroExtAL, VoidTy, Int32Ty, Int32Ty);
    SanCovTraceConstCmpFunction[3] = M.getOrInsertFunction(SanCovTraceConstCmp8, VoidTy, Int64Ty, Int64Ty);

    {
        AttributeList AL;
        AL = AL.addParamAttribute(*C, 0, Attribute::ZExt);
        SanCovTraceDivFunction[0] = M.getOrInsertFunction(SanCovTraceDiv4, AL, VoidTy, IRB.getInt32Ty());
    }

    SanCovTraceDivFunction[1] = M.getOrInsertFunction(SanCovTraceDiv8, VoidTy, Int64Ty);
    SanCovTraceGepFunction    = M.getOrInsertFunction(SanCovTraceGep, VoidTy, IntptrTy);
    SanCovTraceSwitchFunction = M.getOrInsertFunction(SanCovTraceSwitchName, VoidTy, Int64Ty, Int64PtrTy);


    Type *ArgTypes[] = {Type::getInt32Ty (*C), Type::getInt8PtrTy(*C), };
    FunctionType *PrintType = FunctionType::get(Type::getVoidTy(*C), ArgTypes, true);          
    DbPrintf =  CurModule->getOrInsertFunction("printf", PrintType);

    Constant *SanCovLowestStackConstant = M.getOrInsertGlobal(SanCovLowestStackName, IntptrTy);
    SanCovLowestStack = dyn_cast<GlobalVariable>(SanCovLowestStackConstant);
    if (!SanCovLowestStack) {
        C->emitError(StringRef("'") + SanCovLowestStackName + "' should not be declared by the user");
        return true;
    }

    SanCovLowestStack->setThreadLocalMode(GlobalValue::ThreadLocalMode::InitialExecTLSModel);
    if (Options.StackDepth && !SanCovLowestStack->isDeclaration())
        SanCovLowestStack->setInitializer(Constant::getAllOnesValue(IntptrTy));

    SanCovTracePC = M.getOrInsertFunction(SanCovTracePCName, VoidTy);
    SanCovTracePCGuard = M.getOrInsertFunction(SanCovTracePCGuardName, VoidTy, Int32PtrTy);

    for (auto &F : M)
        instrumentFunction(F, DTCallback, PDTCallback);

    Function *Ctor = nullptr;

    if (FunctionGuardArray) {
        Ctor = CreateInitCallsForSections(M, SanCovModuleCtorTracePcGuardName,
                                          SanCovTracePCGuardInitName, Int32PtrTy,
                                          SanCovGuardsSectionName);
    }
  
    if (Function8bitCounterArray) {
        Ctor = CreateInitCallsForSections(M, SanCovModuleCtor8bitCountersName,
                                          SanCov8bitCountersInitName, Int8PtrTy,
                                          SanCovCountersSectionName);
    }
  
    if (FunctionBoolArray) {
        Ctor = CreateInitCallsForSections(M, SanCovModuleCtorBoolFlagName,
                                          SanCovBoolFlagInitName, Int1PtrTy,
                                          SanCovBoolFlagSectionName);
    }

    if (Ctor && Options.PCTable) {
        auto SecStartEnd = CreateSecStartEnd(M, SanCovPCsSectionName, IntptrPtrTy);
        FunctionCallee InitFunction = declareSanitizerInitFunction(M, SanCovPCsInitName, {IntptrPtrTy, IntptrPtrTy});
        IRBuilder<> IRBCtor(Ctor->getEntryBlock().getTerminator());
        IRBCtor.CreateCall(InitFunction, {SecStartEnd.first, SecStartEnd.second});
    }

    // We don't reference these arrays directly in any of our runtime functions,
    // so we need to prevent them from being dead stripped.
    if (TargetTriple.isOSBinFormatMachO()) appendToUsed(M, GlobalsToAppendToUsed);
    appendToCompilerUsed(M, GlobalsToAppendToCompilerUsed);

    if (!be_quiet) {
        if (!instr)
            WARNF("No instrumentation targets found.");
        else {

            char modeline[100];
            snprintf(modeline, sizeof(modeline), "%s%s%s%s%s",
                     getenv("AFL_HARDEN") ? "hardened" : "non-hardened",
                     getenv("AFL_USE_ASAN") ? ", ASAN" : "",
                     getenv("AFL_USE_MSAN") ? ", MSAN" : "",
                     getenv("AFL_USE_CFISAN") ? ", CFISAN" : "",
                     getenv("AFL_USE_UBSAN") ? ", UBSAN" : "");
            OKF("Instrumented %u locations with no collisions (%s mode).", instr, modeline);

        }

    }

    return true;
}

// True if block has successors and it dominates all of them.
bool isFullDominator(const BasicBlock *BB, const DominatorTree *DT) {

    if (succ_begin(BB) == succ_end(BB)) return false;

    for (const BasicBlock *SUCC : make_range(succ_begin(BB), succ_end(BB))) {
        if (!DT->dominates(BB, SUCC)) return false;
    }

    return true;
}

// True if block has predecessors and it postdominates all of them.
bool isFullPostDominator(const BasicBlock *BB, const PostDominatorTree *PDT) {

    if (pred_begin(BB) == pred_end(BB)) return false;

    for (const BasicBlock *PRED : make_range(pred_begin(BB), pred_end(BB))) {

        if (!PDT->dominates(BB, PRED)) return false;

    }

    return true;
}

bool shouldInstrumentBlock(const Function &F, const BasicBlock *BB,
                                      const DominatorTree *           DT,
                                      const PostDominatorTree *       PDT,
                                      const SanitizerCoverageOptions &Options) {

    // Don't insert coverage for blocks containing nothing but unreachable: we
    // will never call __sanitizer_cov() for them, so counting them in
    // NumberOfInstrumentedBlocks() might complicate calculation of code coverage
    // percentage. Also, unreachable instructions frequently have no debug
    // locations.
    if (isa<UnreachableInst>(BB->getFirstNonPHIOrDbgOrLifetime())) return false;

    // Don't insert coverage into blocks without a valid insertion point
    // (catchswitch blocks).
    if (BB->getFirstInsertionPt() == BB->end()) return false;

    if (Options.NoPrune || &F.getEntryBlock() == BB) return true;

    if (Options.CoverageType == SanitizerCoverageOptions::SCK_Function && &F.getEntryBlock() != BB)
        return false;

    // Do not instrument full dominators, or full post-dominators with multiple
    // predecessors. 
    return !isFullDominator(BB, DT) &&
           !(isFullPostDominator(BB, PDT) && !BB->getSinglePredecessor());

}

// Returns true iff From->To is a backedge.
// A twist here is that we treat From->To as a backedge if
//   * To dominates From or
//   * To->UniqueSuccessor dominates From
bool IsBackEdge(BasicBlock *From, BasicBlock *To, const DominatorTree *DT) {

    if (DT->dominates(To, From)) return true;
    if (auto Next = To->getUniqueSuccessor())
        if (DT->dominates(Next, From)) return true;
    
    return false;
}

// Prunes uninteresting Cmp instrumentation:
//   * CMP instructions that feed into loop backedge branch.
//
// Note that Cmp pruning is controlled by the same flag as the
// BB pruning.
bool IsInterestingCmp(ICmpInst *CMP, const DominatorTree *DT,
                              const SanitizerCoverageOptions &Options) {

    if (!Options.NoPrune)
        if (CMP->hasOneUse())
            if (auto BR = dyn_cast<BranchInst>(CMP->user_back()))
                for (BasicBlock *B : BR->successors())
                    if (IsBackEdge(BR->getParent(), B, DT)) return false;

    return true;
}

void ModuleSanitizerCoverage::instrumentFunction(Function &F, DomTreeCallback DTCallback, PostDomTreeCallback PDTCallback) {

    if (F.empty()) return;
    if (!isInInstrumentList(&F)) return;

    if (F.getName().find(".module_ctor") != std::string::npos)
        return;  // Should not instrument sanitizer init functions.
     
    if (F.getName().startswith("__sanitizer_"))
        return;  // Don't instrument __sanitizer_* callbacks.
     
    // Don't touch available_externally functions, their actual body is elewhere.
    if (F.getLinkage() == GlobalValue::AvailableExternallyLinkage) return;
    
    // Don't instrument MSVC CRT configuration helpers. They may run before normal
    // initialization.
    if (F.getName() == "__local_stdio_printf_options" ||
        F.getName() == "__local_stdio_scanf_options")
        return;

    if (strstr (F.getName().data (), "PyInit_") != 0)
    {
        errs ()<<"No need to instrument "<<F.getName()<<"\r\n";
        return;
    }
    
    if (isa<UnreachableInst>(F.getEntryBlock().getTerminator())) return;
    
    // Don't instrument functions using SEH for now. Splitting basic blocks like
    // we do for coverage breaks WinEHPrepare.
    // FIXME: Remove this when SEH no longer uses landingpad pattern matching.
    if (F.hasPersonalityFn() && isAsynchronousEHPersonality(classifyEHPersonality(F.getPersonalityFn())))
        return;
    
    if (Options.CoverageType >= SanitizerCoverageOptions::SCK_Edge)
        SplitAllCriticalEdges(F, CriticalEdgeSplittingOptions().setIgnoreUnreachableDests());
  
    SmallVector<Instruction *, 8>       IndirCalls;
    SmallVector<BasicBlock *, 16>       BlocksToInstrument;
    SmallVector<Instruction *, 8>       CmpTraceTargets;
    SmallVector<Instruction *, 8>       SwitchTraceTargets;
    SmallVector<BinaryOperator *, 8>    DivTraceTargets;
    SmallVector<GetElementPtrInst *, 8> GepTraceTargets;
    ModuleDuCov MDu (*CurModule, &F);

    const DominatorTree *    DT  = DTCallback(F);
    const PostDominatorTree *PDT = PDTCallback(F);
    bool              IsLeafFunc = true;

    //errs ()<<"=========================== "<<F.getName ()<<"=========================== \r\n";
    for (auto &BB : F) {

        if (shouldInstrumentBlock(F, &BB, DT, PDT, Options)) {
            BlocksToInstrument.push_back(&BB);
        }
            
        for (auto &Inst : BB) {

            if (Options.IndirectCalls) {
                CallBase *CB = dyn_cast<CallBase>(&Inst);
                if (CB && !CB->getCalledFunction()) {
                    IndirCalls.push_back(&Inst);
                }
            }

            if (ICmpInst *CMP = dyn_cast<ICmpInst>(&Inst)) {
                if (IsInterestingCmp(CMP, DT, Options)) {
                    if (Options.TraceCmp)
                        CmpTraceTargets.push_back(&Inst);
                }
            }

            if (isa<SwitchInst>(&Inst)) {
                if (Options.TraceCmp)
                    SwitchTraceTargets.push_back(&Inst);
            }

            if (Options.TraceDiv) {
                if (BinaryOperator *BO = dyn_cast<BinaryOperator>(&Inst))
                    if (BO->getOpcode() == Instruction::SDiv ||
                        BO->getOpcode() == Instruction::UDiv)
                        DivTraceTargets.push_back(BO);
            }
                        
            if (Options.TraceGep) {
                if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(&Inst))
                    GepTraceTargets.push_back(GEP);
            }
            
            if (Options.StackDepth) {
                if (isa<InvokeInst>(Inst) || (isa<CallInst>(Inst) && !isa<IntrinsicInst>(Inst)))
                    IsLeafFunc = false;
            }
        }

    }

    DB_PRINT("Instrument %s -> "
             "BlocksToInstrument: %lu IndirCalls:%lu Cmps:%lu Switch:%lu Divs:%lu Gep:%lu Du:%u\r\n",
             F.getName().data(), 
             BlocksToInstrument.size(), IndirCalls.size(), CmpTraceTargets.size(), 
             SwitchTraceTargets.size(), DivTraceTargets.size(), GepTraceTargets.size(), MDu.Size ());

    MDu.CollectDus();
    InjectCoverage(F, MDu, BlocksToInstrument, IsLeafFunc);
    InjectCoverageForIndirectCalls(F, IndirCalls);
    InjectTraceForCmp(F, CmpTraceTargets);
    InjectTraceForSwitch(F, SwitchTraceTargets);
    InjectTraceForDiv(F, DivTraceTargets);
    InjectTraceForGep(F, GepTraceTargets);

}

GlobalVariable *ModuleSanitizerCoverage::CreateFunctionLocalArrayInSection(size_t NumElements, Function &F, 
                                                                                            Type *Ty, const char *Section) {

    ArrayType *ArrayTy = ArrayType::get(Ty, NumElements);
    auto       Array = new GlobalVariable(*CurModule, ArrayTy, false, GlobalVariable::PrivateLinkage,
                                          Constant::getNullValue(ArrayTy), "__sancov_gen_");
    
#if LLVM_VERSION_MAJOR > 12
    if (TargetTriple.supportsCOMDAT() && (TargetTriple.isOSBinFormatELF() || !F.isInterposable()))
        if (auto Comdat = getOrCreateFunctionComdat(F, TargetTriple))
            Array->setComdat(Comdat);
#else
    if (TargetTriple.supportsCOMDAT() && !F.isInterposable())
        if (auto Comdat = GetOrCreateFunctionComdat(F, TargetTriple, CurModuleUniqueId))
            Array->setComdat(Comdat);
#endif

    Array->setSection(getSectionName(Section));
#if LLVM_MAJOR > 10 || (LLVM_MAJOR == 10 && LLVM_MINOR > 0)
    Array->setAlignment(Align(DL->getTypeStoreSize(Ty).getFixedSize()));
#else
    Array->setAlignment(Align(4));  // cheating
#endif

    GlobalsToAppendToUsed.push_back(Array);
    GlobalsToAppendToCompilerUsed.push_back(Array);
    MDNode *MD = MDNode::get(F.getContext(), ValueAsMetadata::get(&F));
    Array->addMetadata(LLVMContext::MD_associated, *MD);

    return Array;
}

GlobalVariable *ModuleSanitizerCoverage::CreatePCArray(Function &F, ArrayRef<BasicBlock *> AllBlocks) {

    size_t N = AllBlocks.size();
    assert(N);
    
    SmallVector<Constant *, 32> PCs;
    IRBuilder<>                 IRB(&*F.getEntryBlock().getFirstInsertionPt());
    for (size_t i = 0; i < N; i++) {

        if (&F.getEntryBlock() == AllBlocks[i]) {
            PCs.push_back((Constant *)IRB.CreatePointerCast(&F, IntptrPtrTy));
            PCs.push_back((Constant *)IRB.CreateIntToPtr(ConstantInt::get(IntptrTy, 1), IntptrPtrTy));
        } else {
            PCs.push_back((Constant *)IRB.CreatePointerCast(BlockAddress::get(AllBlocks[i]), IntptrPtrTy));
            PCs.push_back((Constant *)IRB.CreateIntToPtr(ConstantInt::get(IntptrTy, 0), IntptrPtrTy));
        }

    }

    auto *PCArray = CreateFunctionLocalArrayInSection(N * 2, F, IntptrPtrTy,
                                                    SanCovPCsSectionName);
    PCArray->setInitializer(ConstantArray::get(ArrayType::get(IntptrPtrTy, N * 2), PCs));
    PCArray->setConstant(true);

    return PCArray;
}

void ModuleSanitizerCoverage::CreateFunctionLocalArrays(Function &F, ArrayRef<BasicBlock *> AllBlocks, uint32_t special) {

    if (Options.TracePCGuard) {
        DB_PRINT("CreateFunctionLocalArrays: TracePCGuard \r\n");
        FunctionGuardArray = CreateFunctionLocalArrayInSection(AllBlocks.size() + special, F, Int32Ty, SanCovGuardsSectionName);
        DB_SHOWINST(__LINE__, *FunctionGuardArray);
    }

    if (Options.Inline8bitCounters) {
        DB_PRINT("CreateFunctionLocalArrays: Inline8bitCounters \r\n");
        Function8bitCounterArray = CreateFunctionLocalArrayInSection(AllBlocks.size(), F, Int8Ty, SanCovCountersSectionName);
    }
  
    /*
        if (Options.InlineBoolFlag)
        FunctionBoolArray = CreateFunctionLocalArrayInSection(
            AllBlocks.size(), F, Int1Ty, SanCovBoolFlagSectionName);
    */
    if (Options.PCTable) {
        DB_PRINT("CreateFunctionLocalArrays: PCTable \r\n");
        FunctionPCsArray = CreatePCArray(F, AllBlocks);
    }
}

bool ModuleSanitizerCoverage::InjectCoverage(Function &       F, ModuleDuCov &MDu,
                                                    ArrayRef<BasicBlock *> AllBlocks,
                                                    bool IsLeafFunc) {

    if (AllBlocks.empty()) return false;

    uint32_t special = 0;
    for (auto &BB : F) {

        for (auto &IN : BB) {

            CallInst *callInst = nullptr;
            if ((callInst = dyn_cast<CallInst>(&IN))) {

                Function *Callee = callInst->getCalledFunction();
                if (!Callee) continue;
                
                if (callInst->getCallingConv() != llvm::CallingConv::C) continue;
                
                StringRef FuncName = Callee->getName();
                if (FuncName.compare(StringRef("__afl_coverage_interesting"))) continue;

                uint32_t id = 1 + instr + (uint32_t)AllBlocks.size() + special++;
                Value *  val = ConstantInt::get(Int32Ty, id);
                callInst->setOperand(1, val);
            }

        }

    }

    CreateFunctionLocalArrays(F, AllBlocks, special);
    for (size_t i = 0, N = AllBlocks.size(); i < N; i++) {
        BasicBlock *BB = AllBlocks[i];
        InjectCoverageAtBlock(F, MDu, *BB, i, IsLeafFunc);
    }

    MDu.RunInject();
    
    instr += special;

    return true;
}

// On every indirect call we call a run-time function
// __sanitizer_cov_indir_call* with two parameters:
//   - callee address,
//   - global cache array that contains CacheSize pointers (zero-initialized).
//     The cache is used to speed up recording the caller-callee pairs.
// The address of the caller is passed implicitly via caller PC.
// CacheSize is encoded in the name of the run-time function.
void ModuleSanitizerCoverage::InjectCoverageForIndirectCalls(Function &F, ArrayRef<Instruction *> IndirCalls) {

    if (IndirCalls.empty()) return;
    assert(Options.TracePC || Options.TracePCGuard ||
           Options.Inline8bitCounters /*|| Options.InlineBoolFlag*/);
    
    for (auto I : IndirCalls) {

        IRBuilder<> IRB(I);
        CallBase &  CB = cast<CallBase>(*I);
        Value *     Callee = CB.getCalledOperand();
        if (isa<InlineAsm>(Callee)) continue;
        IRB.CreateCall(SanCovTracePCIndir, IRB.CreatePointerCast(Callee, IntptrTy));
    }
}

// For every switch statement we insert a call:
// __sanitizer_cov_trace_switch(CondValue,
//      {NumCases, ValueSizeInBits, Case0Value, Case1Value, Case2Value, ... })

void ModuleSanitizerCoverage::InjectTraceForSwitch(Function &, ArrayRef<Instruction *> SwitchTraceTargets) {

  for (auto I : SwitchTraceTargets) {

        if (SwitchInst *SI = dyn_cast<SwitchInst>(I)) {

              IRBuilder<>                 IRB(I);
              SmallVector<Constant *, 16> Initializers;
              Value *                     Cond = SI->getCondition();
              if (Cond->getType()->getScalarSizeInBits() >
                  Int64Ty->getScalarSizeInBits())
                    continue;
              
              Initializers.push_back(ConstantInt::get(Int64Ty, SI->getNumCases()));
              Initializers.push_back(ConstantInt::get(Int64Ty, Cond->getType()->getScalarSizeInBits()));
              
              if (Cond->getType()->getScalarSizeInBits() < Int64Ty->getScalarSizeInBits())
                    Cond = IRB.CreateIntCast(Cond, Int64Ty, false);
              for (auto It : SI->cases()) {

                    Constant *C = It.getCaseValue();
                    if (C->getType()->getScalarSizeInBits() < Int64Ty->getScalarSizeInBits())
                        C = ConstantExpr::getCast(CastInst::ZExt, It.getCaseValue(), Int64Ty);
                    Initializers.push_back(C);
              }

              llvm::sort(drop_begin(Initializers, 2), [](const Constant *A, const Constant *B) {

                       return cast<ConstantInt>(A)->getLimitedValue() <
                              cast<ConstantInt>(B)->getLimitedValue();

                     });

              ArrayType *ArrayOfInt64Ty = ArrayType::get(Int64Ty, Initializers.size());
              GlobalVariable *GV = new GlobalVariable(*CurModule, ArrayOfInt64Ty, false, GlobalVariable::InternalLinkage,
                                                      ConstantArray::get(ArrayOfInt64Ty, Initializers), "__sancov_gen_cov_switch_values");
              IRB.CreateCall(SanCovTraceSwitchFunction,
                             {Cond, IRB.CreatePointerCast(GV, Int64PtrTy)});

        }
    }

}

void ModuleSanitizerCoverage::InjectTraceForDiv(Function &, ArrayRef<BinaryOperator *> DivTraceTargets) {

    for (auto BO : DivTraceTargets) {

        IRBuilder<> IRB(BO);
        Value *     A1 = BO->getOperand(1);
        
        if (isa<ConstantInt>(A1)) continue;
        if (!A1->getType()->isIntegerTy()) continue;
        
        uint64_t TypeSize = DL->getTypeStoreSizeInBits(A1->getType());
        
        int      CallbackIdx = TypeSize == 32 ? 0 : TypeSize == 64 ? 1 : -1;
        if (CallbackIdx < 0) continue;
        
        auto Ty = Type::getIntNTy(*C, TypeSize);
        IRB.CreateCall(SanCovTraceDivFunction[CallbackIdx],
                       {IRB.CreateIntCast(A1, Ty, true)});

    }

}

void ModuleSanitizerCoverage::InjectTraceForGep(Function &, ArrayRef<GetElementPtrInst *> GepTraceTargets) {

    for (auto GEP : GepTraceTargets) {

        IRBuilder<> IRB(GEP);
        for (Use &Idx : GEP->indices())
            if (!isa<ConstantInt>(Idx) && Idx->getType()->isIntegerTy())
                IRB.CreateCall(SanCovTraceGepFunction, {IRB.CreateIntCast(Idx, IntptrTy, true)});

    }

}

void ModuleSanitizerCoverage::InjectTraceForCmp(Function &, ArrayRef<Instruction *> CmpTraceTargets) {

    for (auto I : CmpTraceTargets) {

        if (ICmpInst *ICMP = dyn_cast<ICmpInst>(I)) {

            IRBuilder<> IRB(ICMP);
            Value *     A0 = ICMP->getOperand(0);
            Value *     A1 = ICMP->getOperand(1);
            if (!A0->getType()->isIntegerTy()) continue;
          
            uint64_t TypeSize = DL->getTypeStoreSizeInBits(A0->getType());
            int      CallbackIdx = TypeSize == 8    ? 0
                                   : TypeSize == 16 ? 1
                                   : TypeSize == 32 ? 2
                                   : TypeSize == 64 ? 3
                                                    : -1;
            if (CallbackIdx < 0) continue;
          
            // __sanitizer_cov_trace_cmp((type_size << 32) | predicate, A0, A1);
            auto CallbackFunc = SanCovTraceCmpFunction[CallbackIdx];
            bool FirstIsConst = isa<ConstantInt>(A0);
            bool SecondIsConst = isa<ConstantInt>(A1);
            // If both are const, then we don't need such a comparison.
            if (FirstIsConst && SecondIsConst) continue;
          
            // If only one is const, then make it the first callback argument.
            if (FirstIsConst || SecondIsConst) {
                CallbackFunc = SanCovTraceConstCmpFunction[CallbackIdx];
                if (SecondIsConst) std::swap(A0, A1);
            }

            auto Ty = Type::getIntNTy(*C, TypeSize);
            IRB.CreateCall(CallbackFunc, {IRB.CreateIntCast(A0, Ty, true),
                                          IRB.CreateIntCast(A1, Ty, true)});

        }

    }
}

void ModuleSanitizerCoverage::InjectCoverageAtBlock(Function &F, ModuleDuCov &MDu,
                                                              BasicBlock &BB, size_t Idx, bool IsLeafFunc) {

    BasicBlock::iterator IP = BB.getFirstInsertionPt();
    bool         IsEntryBB  = (&BB == &F.getEntryBlock());

    if (IsEntryBB) {
        // Keep allocas and llvm.localescape calls in the entry block.  Even
        // if we aren't splitting the block, it's nice for allocas to be before
        // calls.
        IP = PrepareToSplitEntryBlock(BB, IP);    
    }

    Instruction *InjectInst = &*IP;
    Instruction *InjectDu = MDu.GetBBFirstInst(&BB);
    if (InjectDu != NULL) {
        errs ()<<"REPLACE: "<<*InjectInst<<" ==== WITH ==== "<<*InjectDu<<"\r\n";
        assert (InjectInst->getParent() == InjectDu->getParent());

        InjectInst = MDu.GetInstrmInst (InjectDu);
        assert (InjectInst != NULL);
        
        MDu.SetInjected(InjectInst);
    }

    IRBuilder<> IRB(InjectInst);

    if (Options.TracePC) {
        IRB.CreateCall(SanCovTracePC);
        //        ->setCannotMerge();  // gets the PC using GET_CALLER_PC.
    }

    if (Options.TracePCGuard) {

        if (IsInjectByInst) {
            InjectCovByInstruction(IRB, Idx);
        }
        else {
            InjectCovByCallee(MDu, IRB, Idx, InjectDu);
        }

        ++instr;
    }

    if (Options.Inline8bitCounters) {

        auto CounterPtr = IRB.CreateGEP(Function8bitCounterArray->getValueType(), Function8bitCounterArray,
                                        {ConstantInt::get(IntptrTy, 0), ConstantInt::get(IntptrTy, Idx)});
        auto Load = IRB.CreateLoad(Int8Ty, CounterPtr);
        auto Inc = IRB.CreateAdd(Load, ConstantInt::get(Int8Ty, 1));
        auto Store = IRB.CreateStore(Inc, CounterPtr);
        SetNoSanitizeMetadata(Load);
        SetNoSanitizeMetadata(Store);
    }

    /*
        if (Options.InlineBoolFlag) {

          auto FlagPtr = IRB.CreateGEP(
              FunctionBoolArray->getValueType(), FunctionBoolArray,
              {ConstantInt::get(IntptrTy, 0), ConstantInt::get(IntptrTy, Idx)});
          auto Load = IRB.CreateLoad(Int1Ty, FlagPtr);
          auto ThenTerm =
              SplitBlockAndInsertIfThen(IRB.CreateIsNull(Load), &*IP, false);
          IRBuilder<> ThenIRB(ThenTerm);
          auto Store = ThenIRB.CreateStore(ConstantInt::getTrue(Int1Ty), FlagPtr);
          SetNoSanitizeMetadata(Load);
          SetNoSanitizeMetadata(Store);

        }
    */

    if (Options.StackDepth && IsEntryBB && !IsLeafFunc) {

        // Check stack depth.  If it's the deepest so far, record it.
        Module *  M = F.getParent();
        Function *GetFrameAddr = Intrinsic::getDeclaration(
            M, Intrinsic::frameaddress,
            IRB.getInt8PtrTy(M->getDataLayout().getAllocaAddrSpace()));
        auto FrameAddrPtr =
            IRB.CreateCall(GetFrameAddr, {Constant::getNullValue(Int32Ty)});
        auto        FrameAddrInt = IRB.CreatePtrToInt(FrameAddrPtr, IntptrTy);
        auto        LowestStack = IRB.CreateLoad(IntptrTy, SanCovLowestStack);
        auto        IsStackLower = IRB.CreateICmpULT(FrameAddrInt, LowestStack);
        auto        ThenTerm = SplitBlockAndInsertIfThen(IsStackLower, &*IP, false);
        IRBuilder<> ThenIRB(ThenTerm);
        auto        Store = ThenIRB.CreateStore(FrameAddrInt, SanCovLowestStack);
        SetNoSanitizeMetadata(LowestStack);
        SetNoSanitizeMetadata(Store);
    }

}

std::string ModuleSanitizerCoverage::getSectionName(const std::string &Section) const {

    if (TargetTriple.isOSBinFormatCOFF()) {

        if (Section == SanCovCountersSectionName) return ".SCOV$CM";
        if (Section == SanCovBoolFlagSectionName) return ".SCOV$BM";
        if (Section == SanCovPCsSectionName) return ".SCOVP$M";
        return ".SCOV$GM";  // For SanCovGuardsSectionName.

    }

    if (TargetTriple.isOSBinFormatMachO()) return "__DATA,__" + Section;
    
    return "__" + Section;
}

std::string ModuleSanitizerCoverage::getSectionStart(const std::string &Section) const {

    if (TargetTriple.isOSBinFormatMachO())
        return "\1section$start$__DATA$__" + Section;

    return "__start___" + Section;
}

std::string ModuleSanitizerCoverage::getSectionEnd(const std::string &Section) const {

    if (TargetTriple.isOSBinFormatMachO())
        return "\1section$end$__DATA$__" + Section;

    return "__stop___" + Section;
}

char ModuleSanitizerCoverageLegacyPass::ID = 0;

INITIALIZE_PASS_BEGIN(ModuleSanitizerCoverageLegacyPass, "sancov",
                      "Pass for instrumenting coverage on functions", false,
                      false)
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
INITIALIZE_PASS_DEPENDENCY(PostDominatorTreeWrapperPass)
INITIALIZE_PASS_END(ModuleSanitizerCoverageLegacyPass, "sancov",
                    "Pass for instrumenting coverage on functions", false,
                    false)

ModulePass *llvm::createModuleSanitizerCoverageLegacyPassPass(const SanitizerCoverageOptions &Options
#if LLVM_MAJOR > 10
                                                              ,
                                                              const std::vector<std::string> &AllowlistFiles,
                                                              const std::vector<std::string> &BlocklistFiles
#endif
                                                              ) {

    return new ModuleSanitizerCoverageLegacyPass(Options
#if LLVM_MAJOR > 10
                                                 ,
                                                 AllowlistFiles, BlocklistFiles
#endif
                                                 );

}

void registerPCGUARDPass(const PassManagerBuilder &, legacy::PassManagerBase &PM) {

    auto p = new ModuleSanitizerCoverageLegacyPass();
    PM.add(p);
}

RegisterStandardPasses RegisterCompTransPass(PassManagerBuilder::EP_OptimizerLast, registerPCGUARDPass);

RegisterStandardPasses RegisterCompTransPass0(PassManagerBuilder::EP_EnabledOnOptLevel0, registerPCGUARDPass);

