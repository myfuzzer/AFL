#ifndef BITFLIP_ENGINE_H
#define BITFLIP_ENGINE_H

#include "../../core/fuzz_context.h"

#define FLIP_BIT(_ar, _b) do { \
    u8* _arf = (u8*)(_ar); \
    u32 _bf = (_b); \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
  } while (0)

// 位翻转算法接口
u8 fuzz_bitflip_1_1(char** argv, fuzz_context_t* ctx);
u8 fuzz_bitflip_2_1(char** argv, fuzz_context_t* ctx);
u8 fuzz_bitflip_4_1(char** argv, fuzz_context_t* ctx);
u8 fuzz_bitflip_8_8(char** argv, fuzz_context_t* ctx);
u8 fuzz_bitflip_16_8(char** argv, fuzz_context_t* ctx);
u8 fuzz_bitflip_32_8(char** argv, fuzz_context_t* ctx);

// 主入口函数
u8 fuzz_bitflip_stages(char** argv, fuzz_context_t* ctx);

#endif