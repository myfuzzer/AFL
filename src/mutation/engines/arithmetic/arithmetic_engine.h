#ifndef ARITHMETIC_ENGINE_H
#define ARITHMETIC_ENGINE_H

#include "../../core/fuzz_context.h"

// 算术运算接口
u8 fuzz_arith_8(char** argv, fuzz_context_t* ctx);
u8 fuzz_arith_16(char** argv, fuzz_context_t* ctx);
u8 fuzz_arith_32(char** argv, fuzz_context_t* ctx);

// 主入口函数
u8 fuzz_arithmetic_stages(char** argv, fuzz_context_t* ctx);

#endif