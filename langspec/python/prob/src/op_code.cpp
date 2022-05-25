#include "op_code.h"
#include "loadbrval.h"
#include <cstddef>
#include <set>


namespace pyprob {

using namespace std;

#define OP_BEGIN STORE_NAME
#define OP_END   169


static string OpCodeList[] = 
{
    "STORE_NAME",
    "DELETE_NAME",
    "UNPACK_SEQUENCE",
    "FOR_ITER",
    "UNPACK_EX",
    "STORE_ATTR",
    "DELETE_ATTR",
    "STORE_GLOBAL",
    "DELETE_GLOBAL",
    "ROT_N",
    "LOAD_CONST",
    "LOAD_NAME",
    "BUILD_TUPLE",
    "BUILD_LIST",
    "BUILD_SET",
    "BUILD_MAP",
    "LOAD_ATTR",
    "COMPARE_OP",
    "IMPORT_NAME",
    "IMPORT_FROM",
    "JUMP_FORWARD",
    "JUMP_IF_FALSE_OR_POP",
    "JUMP_IF_TRUE_OR_POP",
    "JUMP_ABSOLUTE",
    "POP_JUMP_IF_FALSE",
    "POP_JUMP_IF_TRUE",
    "LOAD_GLOBAL",
    "IS_OP",
    "CONTAINS_OP",
    "RERAISE",
    "COPY",
    "JUMP_IF_NOT_EXC_MATCH",
    "LOAD_GLOBAL_ADAPTIVE",
    "LOAD_GLOBAL_MODULE",
    "LOAD_FAST",
    "STORE_FAST",
    "DELETE_FAST",
    "LOAD_GLOBAL_BUILTIN",
    "LOAD_METHOD_ADAPTIVE",
    "GEN_START",
    "RAISE_VARARGS",
    "CALL_FUNCTION",
    "MAKE_FUNCTION",
    "BUILD_SLICE",
    "LOAD_METHOD_CACHED",
    "MAKE_CELL",
    "LOAD_CLOSURE",
    "LOAD_DEREF",
    "STORE_DEREF",
    "DELETE_DEREF",
    "LOAD_METHOD_CLASS",
    "CALL_FUNCTION_KW",
    "CALL_FUNCTION_EX",
    "LOAD_METHOD_MODULE",
    "EXTENDED_ARG",
    "LIST_APPEND",
    "SET_ADD",
    "MAP_ADD",
    "LOAD_CLASSDEREF",
    "LOAD_METHOD_NO_DICT",
    "STORE_ATTR_ADAPTIVE",
    "STORE_ATTR_INSTANCE_VALUE",
    "MATCH_CLASS",
    "STORE_ATTR_SLOT",
    "STORE_ATTR_WITH_HINT",
    "FORMAT_VALUE",
    "BUILD_CONST_KEY_MAP",
    "BUILD_STRING",
    "LOAD_FAST__LOAD_FAST",
    "STORE_FAST__LOAD_FAST",
    "LOAD_METHOD",
    "CALL_METHOD",
    "LIST_EXTEND",
    "SET_UPDATE",
    "DICT_MERGE",
    "DICT_UPDATE",
    "CALL_METHOD_KW",
    "LOAD_FAST__LOAD_CONST",
    "LOAD_CONST__LOAD_FAST",
    "STORE_FAST__STORE_FAST"

};


string Op2Name (int Opcode)
{
    if (Opcode < OP_BEGIN || Opcode > OP_END)
    {
        return "UNKNOWN";
    }

    Opcode = Opcode - OP_BEGIN;
    return OpCodeList[Opcode];
}



}  
