#ifndef INTERESTING_ENGINE_H
#define INTERESTING_ENGINE_H

#include "../../core/fuzz_context.h"

// 特殊值算法接口
u8 fuzz_interest_8(char** argv, fuzz_context_t* ctx);
u8 fuzz_interest_16(char** argv, fuzz_context_t* ctx);
u8 fuzz_interest_32(char** argv, fuzz_context_t* ctx);

// 主入口函数
u8 fuzz_interesting_stages(char** argv, fuzz_context_t* ctx);

#endif