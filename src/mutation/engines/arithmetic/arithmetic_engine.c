#include "arithmetic_engine.h"

u8 fuzz_arithmetic_stages(char** argv, fuzz_context_t* ctx) {
    
    if (no_arith) return 0;
    
    // 8位算术运算
    if (fuzz_arith_8(argv, ctx)) return 1;
    
    // 16位算术运算
    if (fuzz_arith_16(argv, ctx)) return 1;
    
    // 32位算术运算  
    if (fuzz_arith_32(argv, ctx)) return 1;
    
    return 0;
}